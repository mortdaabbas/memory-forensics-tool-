import argparse
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from fmem.context import MemoryContext
from fmem.layers import PhysicalLayer, Windowsx64TranslationLayer
from fmem.plugins import (
    DllList,
    NetScan,
    PsList,
    PsScan,
    create_demo_memory_file,
    hash_process_by_pid,
    dump_process_memory_by_pid,
    physical_process_carver,
)
from fmem.structures import CR3Detector, REAL_EPROCESS_LAYOUT


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="fmem memory forensics framework CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the memory image file.",
    )
    parser.add_argument(
        "--cr3",
        type=lambda x: int(x, 0),
        default=None,
        help="Explicit CR3/DTB value to use for the translation layer.",
    )
    parser.add_argument(
        "--profile",
        choices=["auto", "win10"],
        default="auto",
        help="Structure profile to use for parsing memory objects.",
    )

    subparsers = parser.add_subparsers(dest="plugin", required=True)

    pslist_parser = subparsers.add_parser(
        "windows.pslist",
        help="Enumerate active processes via the Windows ActiveProcessLinks chain.",
    )
    pslist_parser.add_argument(
        "--start-eprocess",
        type=lambda x: int(x, 0),
        default=0x1000,
        help="Virtual address of the first EPROCESS entry (default: 0x1000).",
    )

    subparsers.add_parser(
        "windows.psscan",
        help="Carve process objects from physical memory by scanning for EPROCESS structures.",
    )

    dlllist_parser = subparsers.add_parser(
        "windows.dlllist",
        help="Enumerate loaded DLLs for a specific process using the PEB loader list.",
    )
    dlllist_parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="Target PID to enumerate DLLs for (default: first visible process).",
    )
    dlllist_parser.add_argument(
        "--start-eprocess",
        type=lambda x: int(x, 0),
        default=0x1000,
        help="Virtual address of the first EPROCESS entry (default: 0x1000).",
    )

    subparsers.add_parser(
        "windows.netscan",
        help="Scan physical memory for network endpoints and correlate with active PIDs.",
    )

    hash_parser = subparsers.add_parser(
        "hash.process",
        help="Hash process memory for a PID using process context.",
    )
    hash_parser.add_argument(
        "--pid",
        type=int,
        required=True,
        help="Target PID to hash.",
    )
    hash_parser.add_argument(
        "--hash",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hash algorithm to use.",
    )

    procdump_parser = subparsers.add_parser(
        "windows.procdump",
        help="Dump the process memory image for a given PID.",
    )
    procdump_parser.add_argument(
        "--pid",
        type=int,
        required=True,
        help="Target PID to dump.",
    )
    procdump_parser.add_argument(
        "--hash",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hash algorithm to use for the dumped file.",
    )

    return parser.parse_args()


def format_table(rows: List[Dict[str, Any]], headers: Iterable[str]) -> None:
    if not rows:
        print("No results found.")
        return

    widths = []
    for header in headers:
        max_width = len(header)
        for row in rows:
            value = str(row.get(header, ""))
            max_width = max(max_width, len(value))
        widths.append(max_width)

    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    header_line = "| " + " | ".join(header.ljust(width) for header, width in zip(headers, widths)) + " |"

    print(separator)
    print(header_line)
    print(separator)
    for row in rows:
        values = [str(row.get(header, "")).ljust(width) for header, width in zip(headers, widths)]
        print("| " + " | ".join(values) + " |")
    print(separator)


def rows_from_dataclass(items: List[Any], fields: List[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        if hasattr(item, "__dataclass_fields__"):
            record = asdict(item)
        elif isinstance(item, dict):
            record = item
        else:
            record = {field: getattr(item, field, "") for field in fields}
        rows.append(record)
    return rows


def create_or_open_image(path: Path) -> None:
    if not path.exists():
        create_demo_memory_file(path)
        logging.getLogger(__name__).debug("Created missing demo image at %s", path)


def main() -> None:
    configure_logging()
    args = parse_cli_args()
    image_path = Path(args.file)
    create_or_open_image(image_path)

    with PhysicalLayer(image_path) as physical_layer:
        detector = CR3Detector(
            physical_layer,
            verification_virtual_addresses=[0x1000, 0xFFFFF80000000000],
        )

        if args.profile == "auto":
            profile = detector.discover_profile()
            logging.getLogger(__name__).debug("Auto-detected profile: %s", profile)
        else:
            profile = args.profile

        start_eprocess_phys: Optional[int] = None
        start_eprocess = getattr(args, "start_eprocess", None)

        physical_layer.cr3 = args.cr3 if args.cr3 is not None else 0x1AE000
        translation_layer = Windowsx64TranslationLayer(
            physical_layer=physical_layer,
            cr3=physical_layer.cr3,
        )
        context = MemoryContext(
            physical_layer=physical_layer,
            translation_layer=translation_layer,
        )
        context.kernel_base = 0xF805C7400000
        logging.getLogger(__name__).info(
            "Volatility 3 values: CR3=0x%X, KernelBase=0x%X",
            physical_layer.cr3,
            context.kernel_base,
        )

        eprocess_layout = REAL_EPROCESS_LAYOUT if profile == "win10" else None

        if args.plugin == "windows.pslist":
            physical_process_carver(physical_layer)

        elif args.plugin == "windows.psscan":
            plugin = PsScan(layout=eprocess_layout if args.profile == "win10" else None)
            entries = plugin.run(context)
            rows = [
                {"PID": entry.pid, "Name": entry.name, "EPROCESS": hex(entry.eprocess)}
                for entry in entries
            ]
            print("\nCarved process list (PsScan):")
            format_table(rows, ["PID", "Name", "EPROCESS"])

        elif args.plugin == "windows.dlllist":
            pslist_plugin = PsList(
                start_eprocess=start_eprocess,
                start_eprocess_phys=start_eprocess_phys,
                layout=eprocess_layout,
            )
            process_entries = pslist_plugin.run(context)
            target_pid = args.pid
            target_pids: List[int]
            if target_pid is not None:
                target_pids = [target_pid]
            else:
                system_process = next((e for e in process_entries if e.pid == 4), None)
                user_pids = [e.pid for e in process_entries if e.pid != 4]
                if system_process is not None:
                    target_pids = [system_process.pid] + user_pids
                elif process_entries:
                    target_pids = [e.pid for e in process_entries]
                else:
                    raise RuntimeError("No processes available to enumerate DLLs.")

            process_names = {entry.pid: entry.name for entry in process_entries}
            rows = []
            for candidate_pid in target_pids:
                dll_plugin = DllList(
                    target_pid=candidate_pid,
                    process_entries=process_entries,
                    eprocess_layout=eprocess_layout,
                )
                candidate_modules = dll_plugin.run(context)
                for module in candidate_modules:
                    rows.append(
                        {
                            "PID": candidate_pid,
                            "Process": process_names.get(candidate_pid, ""),
                            "DLL": module["BaseDllName"],
                            "Base": hex(module["DllBase"]),
                            "Size": module["SizeOfImage"],
                        }
                    )

            if target_pid is not None:
                print(f"\nDLL list for PID {target_pid}:")
            else:
                print("\nDLL list:")
            format_table(rows, ["PID", "Process", "DLL", "Base", "Size"])

        elif args.plugin == "windows.netscan":
            netscan_plugin = NetScan()
            connections = netscan_plugin.run(context)
            rows = [
                {
                    "Protocol": connection["Protocol"],
                    "Local": f"{connection['LocalAddress']}:{connection['LocalPort']}",
                    "Remote": f"{connection['RemoteAddress']}:{connection['RemotePort']}",
                    "Status": connection.get("Status", "ACTIVE"),
                    "PID": connection["OwningPID"],
                }
                for connection in connections
            ]
            print("\nNetwork connections:")
            format_table(rows, ["Protocol", "Local", "Remote", "Status", "PID"])

        elif args.plugin == "hash.process":
            result = hash_process_by_pid(
                context=context,
                target_pid=args.pid,
                start_eprocess=start_eprocess,
                eprocess_layout=eprocess_layout,
                hash_algorithm=args.hash,
            )
            print(f"\nProcess hash for PID {args.pid}:")
            format_table([result], ["PID", "Process", "Algorithm", "Hash", "ModuleCount", "BytesHashed"])

        elif args.plugin == "windows.procdump":
            result = dump_process_memory_by_pid(
                context=context,
                target_pid=args.pid,
                start_eprocess=start_eprocess,
                eprocess_layout=eprocess_layout,
                output_dir=image_path.parent,
                hash_algorithm=args.hash,
            )
            print(f"\nProcess dump for PID {args.pid}:")
            format_table([result], ["PID", "Process", "Dump File", "Bytes", "Algorithm", "Hash"])


if __name__ == "__main__":
    main()
