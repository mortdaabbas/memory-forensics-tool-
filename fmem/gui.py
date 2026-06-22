import contextlib
import hashlib
import io
import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .context import MemoryContext
from .layers import PhysicalLayer, Windowsx64TranslationLayer
from .plugins import DllList, NetScan, PsList, PsScan, create_demo_memory_file, physical_process_carver
from .structures import CR3Detector, REAL_EPROCESS_LAYOUT

log = logging.getLogger(__name__)


DEFAULT_CR3 = 0x1AE000
DEFAULT_KERNEL_BASE = 0xF805C7400000
DEFAULT_DUMP_SIZE = 64 * 1024 * 1024
HASH_ALGORITHMS = ("md5", "sha1", "sha256")
KERNEL_POINTER_THRESHOLD = 0xFFFF800000000000


class FmemGui(tk.Tk):
    """Tkinter front end for the fmem plugin workflow."""

    def __init__(self) -> None:
        super().__init__()
        self.title("fmem Memory Forensics")
        self.geometry("1120x720")
        self.minsize(860, 520)

        self.result_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.worker: Optional[threading.Thread] = None

        self.image_path_var = tk.StringVar()
        self.profile_var = tk.StringVar(value="auto")
        self.cr3_var = tk.StringVar(value=hex(DEFAULT_CR3))
        self.start_eprocess_var = tk.StringVar(value="0x1000")
        self.pid_var = tk.StringVar()
        self.hash_algorithm_var = tk.StringVar(value="sha256")
        self.status_var = tk.StringVar(value="Select a memory image and run a plugin.")

        self._build_ui()
        self.after(100, self._poll_results)

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        source_frame = ttk.Frame(self, padding=(12, 12, 12, 6))
        source_frame.grid(row=0, column=0, sticky="ew")
        source_frame.columnconfigure(1, weight=1)

        ttk.Label(source_frame, text="Memory image").grid(row=0, column=0, sticky="w")
        ttk.Entry(source_frame, textvariable=self.image_path_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(source_frame, text="Browse", command=self._browse_image).grid(row=0, column=2, sticky="e")

        options_frame = ttk.Frame(self, padding=(12, 0, 12, 8))
        options_frame.grid(row=1, column=0, sticky="ew")
        for column in range(10):
            options_frame.columnconfigure(column, weight=0)
        options_frame.columnconfigure(9, weight=1)

        ttk.Label(options_frame, text="Profile").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            options_frame,
            textvariable=self.profile_var,
            values=("auto", "mock", "win10"),
            width=10,
            state="readonly",
        ).grid(row=0, column=1, sticky="w", padx=(6, 16))

        ttk.Label(options_frame, text="CR3").grid(row=0, column=2, sticky="w")
        ttk.Entry(options_frame, textvariable=self.cr3_var, width=16).grid(row=0, column=3, sticky="w", padx=(6, 16))

        ttk.Label(options_frame, text="Start EPROCESS").grid(row=0, column=4, sticky="w")
        ttk.Entry(options_frame, textvariable=self.start_eprocess_var, width=16).grid(
            row=0,
            column=5,
            sticky="w",
            padx=(6, 16),
        )

        ttk.Label(options_frame, text="Target PID").grid(row=0, column=6, sticky="w")
        ttk.Entry(options_frame, textvariable=self.pid_var, width=12).grid(row=0, column=7, sticky="w", padx=(6, 16))

        ttk.Label(options_frame, text="Hash").grid(row=0, column=8, sticky="w")
        ttk.Combobox(
            options_frame,
            textvariable=self.hash_algorithm_var,
            values=HASH_ALGORITHMS,
            width=9,
            state="readonly",
        ).grid(row=0, column=9, sticky="w", padx=(6, 0))

        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        body.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 8))

        action_frame = ttk.Frame(body, padding=8)
        body.add(action_frame, weight=0)

        ttk.Button(action_frame, text="PsList", command=lambda: self._start_plugin("windows.pslist")).grid(
            row=0,
            column=0,
            sticky="ew",
            pady=3,
        )
        ttk.Button(action_frame, text="PsScan", command=lambda: self._start_plugin("windows.psscan")).grid(
            row=1,
            column=0,
            sticky="ew",
            pady=3,
        )
        ttk.Button(action_frame, text="DllList", command=lambda: self._start_plugin("windows.dlllist")).grid(
            row=2,
            column=0,
            sticky="ew",
            pady=3,
        )
        ttk.Button(action_frame, text="NetScan", command=lambda: self._start_plugin("windows.netscan")).grid(
            row=3,
            column=0,
            sticky="ew",
            pady=3,
        )
        ttk.Button(action_frame, text="Dump PID", command=lambda: self._start_plugin("windows.procdump")).grid(
            row=4,
            column=0,
            sticky="ew",
            pady=(18, 3),
        )
        ttk.Button(action_frame, text="Hash Image", command=lambda: self._start_plugin("hash.image")).grid(
            row=5,
            column=0,
            sticky="ew",
            pady=3,
        )
        ttk.Button(action_frame, text="Clear", command=self._clear_table).grid(row=6, column=0, sticky="ew", pady=(18, 3))

        table_frame = ttk.Frame(body)
        body.add(table_frame, weight=1)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        self.table = ttk.Treeview(table_frame, show="headings")
        self.table.grid(row=0, column=0, sticky="nsew")
        y_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.table.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        status = ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(12, 0, 12, 10))
        status.grid(row=3, column=0, sticky="ew")

    def _browse_image(self) -> None:
        selected = filedialog.askopenfilename(title="Select memory image")
        if selected:
            self.image_path_var.set(selected)

    def _start_plugin(self, plugin_name: str) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("fmem", "A plugin is already running.")
            return

        image_path = self.image_path_var.get().strip()
        if not image_path:
            messagebox.showwarning("fmem", "Choose a memory image first.")
            return

        try:
            cr3 = int(self.cr3_var.get().strip(), 0)
            start_eprocess = int(self.start_eprocess_var.get().strip(), 0)
            target_pid = int(self.pid_var.get().strip(), 0) if self.pid_var.get().strip() else None
        except ValueError as exc:
            messagebox.showerror("fmem", f"Invalid numeric value: {exc}")
            return

        if plugin_name == "windows.procdump" and target_pid is None:
            messagebox.showwarning("fmem", "Enter a target PID before dumping process memory.")
            return

        self.status_var.set(f"Running {plugin_name}...")
        self._clear_table()

        args = {
            "image_path": Path(image_path),
            "profile": self.profile_var.get(),
            "cr3": cr3,
            "start_eprocess": start_eprocess,
            "target_pid": target_pid,
            "plugin_name": plugin_name,
            "hash_algorithm": self.hash_algorithm_var.get(),
        }
        self.worker = threading.Thread(target=self._run_worker, kwargs=args, daemon=True)
        self.worker.start()

    def _run_worker(
        self,
        image_path: Path,
        profile: str,
        cr3: int,
        start_eprocess: int,
        target_pid: Optional[int],
        plugin_name: str,
        hash_algorithm: str,
    ) -> None:
        try:
            title, headers, rows = run_plugin_for_gui(
                image_path=image_path,
                profile=profile,
                cr3=cr3,
                start_eprocess=start_eprocess,
                target_pid=target_pid,
                plugin_name=plugin_name,
                hash_algorithm=hash_algorithm,
            )
            self.result_queue.put(("result", (title, headers, rows)))
        except Exception as exc:
            log.exception("GUI plugin run failed")
            self.result_queue.put(("error", str(exc)))

    def _poll_results(self) -> None:
        try:
            while True:
                kind, payload = self.result_queue.get_nowait()
                if kind == "result":
                    title, headers, rows = payload
                    self._set_rows(headers, rows)
                    self.status_var.set(f"{title}: {len(rows)} row(s)")
                elif kind == "error":
                    self.status_var.set("Plugin failed.")
                    messagebox.showerror("fmem", payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_results)

    def _clear_table(self) -> None:
        self.table.delete(*self.table.get_children())

    def _set_rows(self, headers: Iterable[str], rows: List[Dict[str, Any]]) -> None:
        headers = list(headers)
        self.table.configure(columns=headers)
        for header in headers:
            self.table.heading(header, text=header)
            self.table.column(header, width=max(120, len(header) * 12), minwidth=80, stretch=True)
        self._clear_table()
        for row in rows:
            self.table.insert("", tk.END, values=[row.get(header, "") for header in headers])


def build_context(image_path: Path, profile: str, cr3: int) -> Tuple[PhysicalLayer, MemoryContext, Optional[Dict[str, Any]]]:
    if not image_path.exists():
        create_demo_memory_file(image_path)

    physical_layer = PhysicalLayer(image_path)
    force_win_profile = image_path.name != "mock_memory.bin"
    selected_profile = "win10" if force_win_profile else profile

    if selected_profile == "auto":
        detector = CR3Detector(
            physical_layer,
            verification_virtual_addresses=[0x1000, 0xFFFFF80000000000],
        )
        selected_profile = detector.discover_profile()

    physical_layer.cr3 = cr3
    context = MemoryContext(
        physical_layer=physical_layer,
        translation_layer=Windowsx64TranslationLayer(physical_layer=physical_layer, cr3=cr3),
    )
    context.kernel_base = DEFAULT_KERNEL_BASE
    eprocess_layout = REAL_EPROCESS_LAYOUT if selected_profile == "win10" else None
    return physical_layer, context, eprocess_layout


def run_plugin_for_gui(
    image_path: Path,
    profile: str,
    cr3: int,
    start_eprocess: int,
    target_pid: Optional[int],
    plugin_name: str,
    hash_algorithm: str = "sha256",
) -> Tuple[str, List[str], List[Dict[str, Any]]]:
    physical_layer, context, eprocess_layout = build_context(image_path, profile, cr3)
    try:
        if plugin_name == "hash.image":
            digest = hash_file(image_path, hash_algorithm)
            rows = [{"File": str(image_path), "Algorithm": hash_algorithm.upper(), "Hash": digest}]
            return "Image Hash", ["File", "Algorithm", "Hash"], rows

        if plugin_name == "windows.pslist":
            with contextlib.redirect_stdout(io.StringIO()):
                entries = physical_process_carver(physical_layer)
            rows = [
                {
                    "PID": entry.pid,
                    "Process": entry.name,
                    "PPID": entry.ppid,
                    "Create Time": entry.create_time,
                    "EPROCESS": hex(entry.eprocess),
                }
                for entry in entries
            ]
            return "PsList", ["PID", "Process", "PPID", "Create Time", "EPROCESS"], rows

        if plugin_name == "windows.psscan":
            entries = PsScan(layout=eprocess_layout).run(context)
            rows = [
                {"PID": entry.pid, "Process": entry.name, "EPROCESS": hex(entry.eprocess)}
                for entry in entries
            ]
            return "PsScan", ["PID", "Process", "EPROCESS"], rows

        if plugin_name == "windows.dlllist":
            with contextlib.redirect_stdout(io.StringIO()):
                process_entries = PsList(
                    start_eprocess=start_eprocess,
                    start_eprocess_phys=None,
                    layout=eprocess_layout,
                ).run(context)
            target_pids = _dll_target_pids(process_entries, target_pid)
            process_names = {entry.pid: entry.name for entry in process_entries}
            rows: List[Dict[str, Any]] = []
            for candidate_pid in target_pids:
                modules = DllList(
                    target_pid=candidate_pid,
                    process_entries=process_entries,
                    eprocess_layout=eprocess_layout,
                ).run(context)
                for module in modules:
                    rows.append(
                        {
                            "PID": candidate_pid,
                            "Process": process_names.get(candidate_pid, ""),
                            "DLL": module["BaseDllName"],
                            "Base": hex(module["DllBase"]),
                            "Size": module["SizeOfImage"],
                        }
                    )
            title = f"DllList PID {target_pid}" if target_pid is not None else "DllList"
            return title, ["PID", "Process", "DLL", "Base", "Size"], rows

        if plugin_name == "windows.netscan":
            connections = NetScan().run(context)
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
            return "NetScan", ["Protocol", "Local", "Remote", "Status", "PID"], rows

        if plugin_name == "windows.procdump":
            if target_pid is None:
                raise ValueError("Target PID is required for process memory dump")
            dump_info = dump_process_memory_by_pid(
                context=context,
                start_eprocess=start_eprocess,
                target_pid=target_pid,
                eprocess_layout=eprocess_layout,
                output_dir=image_path.parent,
                hash_algorithm=hash_algorithm,
            )
            return "Process Dump", ["PID", "Process", "Dump File", "Offset", "Size", "Algorithm", "Hash"], [dump_info]

        raise ValueError(f"Unsupported plugin: {plugin_name}")
    finally:
        physical_layer.close()


def hash_file(path: Path, algorithm: str) -> str:
    normalized = algorithm.lower()
    if normalized not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    digest = hashlib.new(normalized)
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dump_process_memory_by_pid(
    context: MemoryContext,
    start_eprocess: int,
    target_pid: int,
    eprocess_layout: Optional[Dict[str, Any]],
    output_dir: Path,
    hash_algorithm: str,
    dump_size: int = DEFAULT_DUMP_SIZE,
) -> Dict[str, Any]:
    with contextlib.redirect_stdout(io.StringIO()):
        process_entries = PsList(
            start_eprocess=start_eprocess,
            start_eprocess_phys=None,
            layout=eprocess_layout,
        ).run(context)

    process = next((entry for entry in process_entries if entry.pid == target_pid), None)
    if process is None:
        raise ValueError(f"Process PID={target_pid} was not found")

    physical_offset = _process_dump_offset(context, int(process.eprocess))
    if physical_offset >= context.physical_layer.size:
        raise ValueError(f"Process PID={target_pid} resolved outside the memory image")

    readable_size = min(dump_size, context.physical_layer.size - physical_offset)
    data = context.physical_layer.read_physical(physical_offset, readable_size)

    safe_name = "".join(char if char.isalnum() or char in ("-", "_", ".") else "_" for char in process.name)
    dump_path = output_dir / f"pid_{target_pid}_{safe_name}_0x{physical_offset:X}.dmp"
    dump_path.write_bytes(data)

    return {
        "PID": target_pid,
        "Process": process.name,
        "Dump File": str(dump_path),
        "Offset": hex(physical_offset),
        "Size": readable_size,
        "Algorithm": hash_algorithm.upper(),
        "Hash": hash_file(dump_path, hash_algorithm),
    }


def _process_dump_offset(context: MemoryContext, eprocess_address: int) -> int:
    if eprocess_address < KERNEL_POINTER_THRESHOLD:
        return eprocess_address
    return context.translation_layer.translate_address(eprocess_address)


def _dll_target_pids(process_entries: List[Any], target_pid: Optional[int]) -> List[int]:
    if target_pid is not None:
        return [target_pid]
    system_process = next((entry for entry in process_entries if entry.pid == 4), None)
    user_pids = [entry.pid for entry in process_entries if entry.pid != 4]
    if system_process is not None:
        return [system_process.pid] + user_pids
    return [entry.pid for entry in process_entries]


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = FmemGui()
    app.mainloop()


if __name__ == "__main__":
    main()
