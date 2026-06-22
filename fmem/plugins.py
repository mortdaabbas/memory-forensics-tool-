import logging
import os
import socket
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .context import MemoryContext
from .layers import PhysicalLayer, Windowsx64TranslationLayer
from .scanners import PhysicalScanner
from .structures import (
    LDR_DATA_TABLE_ENTRY_LAYOUT,
    NETWORK_ENDPOINT_LAYOUT,
    PEB_LAYOUT,
    PEB_LDR_DATA_LAYOUT,
    REAL_EPROCESS_LAYOUT,
    StructureParser,
)

log = logging.getLogger(__name__)

FieldLayout = Dict[str, Any]
StructureLayout = Dict[str, FieldLayout]

REAL_PEB_OFFSET = 0x550
REAL_LDR_DLL_BASE_OFFSET = 0x30
REAL_LDR_SIZE_OF_IMAGE_OFFSET = 0x40
REAL_LDR_BASE_DLL_NAME_OFFSET = 0x58
UNICODE_STRING_LENGTH_OFFSET = 0x0
UNICODE_STRING_BUFFER_OFFSET = 0x8

RAW_MEMORY_IMAGE = Path(r"E:\memorydump\Memory\memory.raw")
CHUNK_SIZE = 50 * 1024 * 1024
NAME_BACKTRACK = 15
KERNEL_POINTER_THRESHOLD = 0xFFFF800000000000
MAX_PROCESS_ID = 500000
SUFFIX_PATTERNS = [b"System\x00", b".exe\x00"]


@dataclass
class ProcessObject:
    pid: int
    name: str
    eprocess: int
    ppid: int
    create_time: str


@dataclass
class ProcessEntry:
    pid: int
    name: str
    eprocess: int
    ppid: Optional[int] = None
    create_time: Optional[str] = None


class BasePlugin(ABC):
    """Abstract base class for memory forensic plugins."""

    @abstractmethod
    def run(self, context: MemoryContext) -> Any:
        """Execute the plugin against the provided memory context."""
        raise NotImplementedError


def win_filetime_to_str(ft: int) -> str:
    if not isinstance(ft, int) or ft <= 0:
        return "N/A"

    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        converted = epoch + timedelta(microseconds=ft / 10)
        if converted.year < 2000 or converted.year > 2030:
            return "N/A"
        return converted.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def _is_printable_ascii(value: str) -> bool:
    return bool(value) and all(0x20 <= ord(char) < 0x7F for char in value)


def _extract_exe_name(raw_file: Any, abs_suffix: int) -> Optional[bytes]:
    if abs_suffix <= 0:
        return None

    start_search = max(0, abs_suffix - NAME_BACKTRACK)
    raw_file.seek(start_search)
    prefix = raw_file.read(abs_suffix - start_search)
    last_null = prefix.rfind(b"\x00")

    if last_null != -1:
        candidate = prefix[last_null + 1 :] + b".exe\x00"
    else:
        candidate = prefix + b".exe\x00"

    if candidate.endswith(b".exe\x00") and len(candidate) > len(b".exe\x00"):
        return candidate
    return None


def _format_table(rows: List[Dict[str, Any]], headers: List[str]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, header in enumerate(headers):
            widths[idx] = max(widths[idx], len(str(row.get(header, ""))))

    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    print(separator)
    print("| " + " | ".join(header.ljust(width) for header, width in zip(headers, widths)) + " |")
    print(separator)
    for row in rows:
        print("| " + " | ".join(str(row.get(header, "")).ljust(width) for header, width in zip(headers, widths)) + " |")
    print(separator)


def physical_process_carver(physical_layer: PhysicalLayer) -> List[ProcessObject]:
    image_path = physical_layer.image_path
    if not image_path.exists():
        log.warning("Raw memory image not found at %s", image_path)
        return []

    entries: Dict[int, ProcessObject] = {}
    overlap = NAME_BACKTRACK + max(len(suffix) for suffix in SUFFIX_PATTERNS)

    with image_path.open("rb") as raw_file:
        raw_file.seek(0, os.SEEK_END)
        file_size = raw_file.tell()

        offset = 0
        while offset < file_size:
            raw_file.seek(offset)
            chunk = raw_file.read(CHUNK_SIZE)
            if not chunk:
                break

            for suffix in SUFFIX_PATTERNS:
                position = 0
                while True:
                    found = chunk.find(suffix, position)
                    if found == -1:
                        break

                    abs_suffix = offset + found
                    if suffix == b".exe\x00":
                        candidate_bytes = _extract_exe_name(raw_file, abs_suffix)
                        if candidate_bytes is None:
                            position = found + 1
                            continue
                        name = candidate_bytes.rstrip(b"\x00").decode("ascii", errors="ignore")
                        name_offset = abs_suffix - len(candidate_bytes) + len(suffix)
                    else:
                        candidate_bytes = b"System\x00"
                        name = "System"
                        name_offset = abs_suffix

                    if not _is_printable_ascii(name):
                        position = found + 1
                        continue

                    eprocess_base = name_offset - 0x5A8
                    if eprocess_base < 0:
                        position = found + 1
                        continue

                    try:
                        raw_file.seek(eprocess_base + 0x448)
                        flink, blink = struct.unpack("<QQ", raw_file.read(16))
                    except Exception:
                        position = found + 1
                        continue

                    if flink < KERNEL_POINTER_THRESHOLD or blink < KERNEL_POINTER_THRESHOLD:
                        position = found + 1
                        continue

                    try:
                        raw_file.seek(eprocess_base + 0x5A8)
                        actual_name = raw_file.read(len(candidate_bytes)).split(b"\x00", 1)[0]
                    except Exception:
                        position = found + 1
                        continue

                    if actual_name != candidate_bytes.rstrip(b"\x00"):
                        position = found + 1
                        continue

                    try:
                        raw_file.seek(eprocess_base + 0x440)
                        pid = int.from_bytes(raw_file.read(4), "little")
                        raw_file.seek(eprocess_base + 0x540)
                        ppid = int.from_bytes(raw_file.read(4), "little")
                        raw_file.seek(eprocess_base + 0x468)
                        create_time_raw = int.from_bytes(raw_file.read(8), "little")
                    except Exception:
                        position = found + 1
                        continue

                    # Allow System (PID 4) with PPID 0; otherwise validate both PID and PPID
                    if pid == 4 and name == "System":
                        # System process: PID must be 4, PPID is allowed to be 0
                        pass
                    elif pid <= 0 or pid >= MAX_PROCESS_ID or ppid <= 0 or ppid >= MAX_PROCESS_ID:
                        position = found + 1
                        continue
                    elif name == "System" and pid != 4:
                        position = found + 1
                        continue
                    elif name != "System" and (pid % 4 != 0 or ppid % 4 != 0):
                        position = found + 1
                        continue

                    create_time = win_filetime_to_str(create_time_raw)
                    if eprocess_base not in entries:
                        entries[eprocess_base] = ProcessObject(
                            pid=pid,
                            name=name,
                            eprocess=eprocess_base,
                            ppid=ppid,
                            create_time=create_time,
                        )

                    position = found + 1

            if len(chunk) <= overlap:
                break
            offset += len(chunk) - overlap

    # Sort with PID 4 (System) first, then by PID ascending
    sorted_entries = sorted(entries.values(), key=lambda item: (item.pid != 4, item.pid))
    
    rows = [
        {
            "PID": obj.pid,
            "Process Name": obj.name,
            "PPID": obj.ppid,
            "Create Time": obj.create_time,
            "EPROCESS": hex(obj.eprocess),
        }
        for obj in sorted_entries
    ]

    if rows:
        print("\nProcess list (Physical fallback PsList):")
        _format_table(rows, ["PID", "Process Name", "PPID", "Create Time", "EPROCESS"])
    else:
        print("\nNo matching process objects found by physical carver.")

    return sorted_entries


class PsList(BasePlugin):
    """Enumerate active processes by walking the ActiveProcessLinks list."""

    DEFAULT_EPROCESS_LAYOUT: StructureLayout = {
        "UniqueProcessId": {"offset": 0x440, "format": "<Q"},
        "ActiveProcessLinks": {"offset": 0x448, "format": "<Q"},
        "ImageFileName": {"offset": 0x5A8, "format": "16s"},
    }

    def __init__(
        self,
        start_eprocess: int,
        start_eprocess_phys: Optional[int] = None,
        layout: Optional[StructureLayout] = None,
        max_entries: int = 128,
    ) -> None:
        self.start_eprocess = start_eprocess
        self.start_eprocess_phys = start_eprocess_phys
        self.layout = layout or self.DEFAULT_EPROCESS_LAYOUT
        self.max_entries = max_entries
        log.debug(
            "Initialized PsList plugin with start_eprocess=0x%X start_eprocess_phys=%s layout=%s",
            self.start_eprocess,
            hex(self.start_eprocess_phys) if self.start_eprocess_phys is not None else None,
            self.layout,
        )

    def run(self, context: MemoryContext) -> List[ProcessObject]:
        try:
            entries = self._walk_active_process_links(context)
            if entries:
                return entries
        except Exception as exc:
            log.debug("PsList chain walk failed: %s", exc)

        log.warning(
            "PsList falling back to physical process carving because the virtual chain walk failed or returned no entries."
        )
        return physical_process_carver(context.physical_layer)

    def _walk_active_process_links(self, context: MemoryContext) -> List[ProcessObject]:
        parser = StructureParser(context, self.layout)
        entries: List[ProcessObject] = []
        visited: Set[int] = set()

        current_eprocess = self.start_eprocess
        while current_eprocess not in visited and len(entries) < self.max_entries:
            try:
                fields = parser.parse(current_eprocess)
            except Exception as exc:
                log.debug(
                    "Failed to parse EPROCESS at virtual 0x%X during PsList walk: %s",
                    current_eprocess,
                    exc,
                )
                break

            pid = int(fields["UniqueProcessId"])
            name = str(fields["ImageFileName"])
            links = int(fields["ActiveProcessLinks"])
            ppid = 0

            entries.append(
                ProcessObject(
                    pid=pid,
                    name=name,
                    eprocess=current_eprocess,
                    ppid=ppid,
                    create_time="N/A",
                )
            )
            visited.add(current_eprocess)

            next_eprocess = links - parser.field_offset("ActiveProcessLinks")
            if next_eprocess == current_eprocess:
                break
            current_eprocess = next_eprocess

        return entries


class DllList(BasePlugin):
    """Traverse a process PEB loader list and enumerate loaded DLLs."""

    def __init__(
        self,
        target_pid: int,
        process_entries: Optional[List[ProcessEntry]] = None,
        eprocess_layout: Optional[Dict[str, Any]] = None,
        max_modules: int = 64,
    ) -> None:
        self.target_pid = target_pid
        self.process_entries = process_entries or []
        self.eprocess_layout = eprocess_layout
        self.max_modules = max_modules
        log.debug(
            "Initialized DllList plugin for PID=%d entries=%s",
            self.target_pid,
            self.process_entries,
        )

    def run(self, context: MemoryContext) -> List[Dict[str, Any]]:
        parser_layout: StructureLayout = dict(self.eprocess_layout or {})
        if "Peb" not in parser_layout:
            peb_offset = REAL_PEB_OFFSET if self._uses_real_eprocess_layout(parser_layout) else 0x30
            parser_layout["Peb"] = {"offset": peb_offset, "format": "<Q"}

        parser = StructureParser(context, parser_layout)
        eprocess_address = self._find_eprocess_address()
        if eprocess_address is None:
            raise ValueError(f"Process PID={self.target_pid} not found in provided process entries")

        peb_address = None
        process_dtb = None
        parse_physical_first = (
            self._uses_real_eprocess_layout(parser_layout)
            and eprocess_address < KERNEL_POINTER_THRESHOLD
        )
        parse_modes = ["physical", "virtual"] if parse_physical_first else ["virtual", "physical"]

        for parse_mode in parse_modes:
            try:
                if parse_mode == "physical":
                    eprocess_fields = parser.parse_physical(eprocess_address)
                else:
                    eprocess_fields = parser.parse(eprocess_address)
                peb_address = int(eprocess_fields["Peb"])
                process_dtb = self._extract_process_dtb(eprocess_fields)
                log.debug(
                    "DllList resolved %s PEB pointer 0x%X for PID=%d",
                    parse_mode,
                    peb_address,
                    self.target_pid,
                )
                if peb_address == 0:
                    log.info(
                        "DllList: Process PID=%d has no user-mode environment block (PEB is null)",
                        self.target_pid,
                    )
                    return []
                break
            except Exception as exc:
                log.debug(
                    "%s EPROCESS parse failed for PID=%d at 0x%X: %s",
                    parse_mode.capitalize(),
                    self.target_pid,
                    eprocess_address,
                    exc,
                )

        if peb_address is not None:
            original_translation_layer = context.translation_layer
            try:
                if process_dtb:
                    context.translation_layer = Windowsx64TranslationLayer(
                        physical_layer=context.physical_layer,
                        cr3=process_dtb,
                    )
                    log.debug(
                        "DllList using process DTB 0x%X for PID=%d user-space PEB walk",
                        process_dtb,
                        self.target_pid,
                    )
                peb_parser = StructureParser(context, PEB_LAYOUT)
                peb_fields = peb_parser.parse(peb_address)
                ldr_address = int(peb_fields["Ldr"])
                return self._walk_loader_list(
                    context,
                    ldr_address,
                    real_layout=self._uses_real_eprocess_layout(parser_layout),
                )
            except Exception as exc:
                log.debug(
                    "Virtual PEB loader walk failed for PID=%d at PEB 0x%X: %s",
                    self.target_pid,
                    peb_address,
                    exc,
                )
            finally:
                context.translation_layer = original_translation_layer

        log.warning(
            "DllList falling back to physical DLL signature carver for PID=%d at EPROCESS 0x%X",
            self.target_pid,
            eprocess_address,
        )
        return self._carve_dlls_from_physical(context, eprocess_address)

    def _walk_loader_list(
        self,
        context: MemoryContext,
        ldr_address: int,
        real_layout: bool = False,
    ) -> List[Dict[str, Any]]:
        if real_layout:
            return self._walk_real_loader_list(context, ldr_address)

        ldr_parser = StructureParser(context, PEB_LDR_DATA_LAYOUT)
        ldr_fields = ldr_parser.parse(ldr_address)
        list_head_address = ldr_address + ldr_parser.field_offset("InLoadOrderModuleList")
        current_link = int(ldr_fields["InLoadOrderModuleList"])

        module_parser = StructureParser(context, LDR_DATA_TABLE_ENTRY_LAYOUT)
        modules: List[Dict[str, Any]] = []
        visited: Set[int] = set()

        while True:
            if (
                current_link == 0
                or current_link == list_head_address
                or current_link in visited
                or len(modules) >= self.max_modules
            ):
                break
            visited.add(current_link)
            module_address = current_link - module_parser.field_offset("InLoadOrderLinks")
            module_fields = module_parser.parse(module_address)
            modules.append({
                "DllBase": int(module_fields["DllBase"]),
                "SizeOfImage": int(module_fields["SizeOfImage"]),
                "BaseDllName": str(module_fields["BaseDllName"]),
            })
            log.info(
                "DllList found DLL %s at 0x%X size=%d",
                module_fields["BaseDllName"],
                module_fields["DllBase"],
                module_fields["SizeOfImage"],
            )
            current_link = int(module_fields["InLoadOrderLinks"])
            if current_link == list_head_address:
                break

        return modules

    def _walk_real_loader_list(self, context: MemoryContext, ldr_address: int) -> List[Dict[str, Any]]:
        list_head_address = ldr_address + PEB_LDR_DATA_LAYOUT["InLoadOrderModuleList"]["offset"]
        current_link = int.from_bytes(context.read_virtual(list_head_address, 8), "little")

        modules: List[Dict[str, Any]] = []
        visited: Set[int] = set()

        while (
            current_link
            and current_link != list_head_address
            and current_link not in visited
            and len(modules) < self.max_modules
        ):
            visited.add(current_link)
            module_address = current_link
            dll_base = int.from_bytes(
                context.read_virtual(module_address + REAL_LDR_DLL_BASE_OFFSET, 8),
                "little",
            )
            size_of_image = int.from_bytes(
                context.read_virtual(module_address + REAL_LDR_SIZE_OF_IMAGE_OFFSET, 4),
                "little",
            )
            base_dll_name = self._read_unicode_string(
                context,
                module_address + REAL_LDR_BASE_DLL_NAME_OFFSET,
            )

            modules.append({
                "DllBase": dll_base,
                "SizeOfImage": size_of_image,
                "BaseDllName": base_dll_name,
            })
            log.info(
                "DllList found DLL %s at 0x%X size=%d",
                base_dll_name,
                dll_base,
                size_of_image,
            )

            current_link = int.from_bytes(context.read_virtual(current_link, 8), "little")
            if current_link == list_head_address:
                break

        return modules

    def _read_unicode_string(self, context: MemoryContext, address: int) -> str:
        length = int.from_bytes(
            context.read_virtual(address + UNICODE_STRING_LENGTH_OFFSET, 2),
            "little",
        )
        if length <= 0:
            return ""

        buffer_address = int.from_bytes(
            context.read_virtual(address + UNICODE_STRING_BUFFER_OFFSET, 8),
            "little",
        )
        if buffer_address == 0:
            return ""

        raw_name = context.read_virtual(buffer_address, length)
        return raw_name.decode("utf-16-le", errors="ignore").rstrip("\x00")

    def _carve_dlls_from_physical(self, context: MemoryContext, eprocess_phys: int) -> List[Dict[str, Any]]:
        physical_layer = context.physical_layer
        page_size = 0x1000
        start = max(0, eprocess_phys - page_size * 4)
        end = min(physical_layer.size, eprocess_phys + page_size * 8)
        size = end - start

        try:
            data = physical_layer.read_physical(start, size)
        except Exception as exc:
            log.debug("DllList fallback physical read failed for PID=%d: %s", self.target_pid, exc)
            return []

        modules: List[Dict[str, Any]] = []
        seen_names: Set[str] = set()
        for signature in [b".dll\x00", b".DLL\x00"]:
            offset = 0
            while True:
                found = data.find(signature, offset)
                if found == -1:
                    break
                begin = data.rfind(b"\x00", 0, found)
                if begin == -1:
                    begin = max(0, found - 128)
                name_bytes = data[begin + 1 : found + len(signature)]
                name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                if name and name.lower().endswith(".dll") and name not in seen_names:
                    seen_names.add(name)
                    modules.append({
                        "DllBase": 0,
                        "SizeOfImage": 0,
                        "BaseDllName": name,
                    })
                offset = found + 1

        if not modules:
            log.warning("DllList physical fallback found no DLL signatures for PID=%d", self.target_pid)
        return modules

    def _find_eprocess_address(self) -> Optional[int]:
        for entry in self.process_entries:
            if entry.pid == self.target_pid:
                return entry.eprocess
        return None

    @staticmethod
    def _uses_real_eprocess_layout(layout: StructureLayout) -> bool:
        return int(layout.get("ImageFileName", {}).get("offset", 0)) == 0x5A8

    @staticmethod
    def _extract_process_dtb(fields: Dict[str, Any]) -> Optional[int]:
        process_dtb = fields.get("DirectoryTableBase")
        if process_dtb is None:
            return None
        process_dtb = int(process_dtb)
        return process_dtb or None


class NetScan(BasePlugin):
    """Scan raw physical memory for network endpoint structures."""

    DEFAULT_SIGNATURES = [b"TcpE", b"UdpA"]

    def __init__(
        self,
        active_pids: Optional[Set[int]] = None,
        signatures: Optional[List[bytes]] = None,
        layout: Optional[Dict[str, Any]] = None,
        signature_offset: int = 0,
    ) -> None:
        self.active_pids = active_pids
        self.signatures = signatures or self.DEFAULT_SIGNATURES
        self.layout = layout or NETWORK_ENDPOINT_LAYOUT
        self.signature_offset = signature_offset
        log.debug(
            "Initialized NetScan plugin with signatures=%s signature_offset=0x%X active_pids=%s",
            self.signatures,
            self.signature_offset,
            self.active_pids,
        )

    def _protocol_for_signature(self, signature: bytes) -> str:
        if signature == b"TcpE":
            return "TCP"
        if signature == b"UdpA":
            return "UDP"
        return "UNKNOWN"

    def run(self, context: MemoryContext) -> List[Dict[str, Any]]:
        scanner = PhysicalScanner(context.physical_layer)
        parser = StructureParser(context, self.layout)
        connections: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, int, str, int, int]] = set()

        for signature in self.signatures:
            matches = scanner.scan(signature)
            protocol = self._protocol_for_signature(signature)
            for match in matches:
                physical_address = match - self.signature_offset
                if physical_address < 0:
                    continue
                try:
                    fields = parser.parse_physical(physical_address)
                except Exception as exc:
                    log.debug(
                        "Failed to parse network endpoint for signature %s at physical 0x%X: %s",
                        signature,
                        physical_address,
                        exc,
                    )
                    continue

                try:
                    pid = int(fields["OwningPID"])
                except Exception:
                    log.debug("Skipping malformed OwningPID field at physical 0x%X", physical_address)
                    continue

                if not self._valid_pid(pid):
                    log.debug("Skipping endpoint with invalid PID=%d at physical 0x%X", pid, physical_address)
                    continue

                try:
                    local_port = int(fields.get("LocalPort", 0))
                    remote_port = int(fields.get("RemotePort", 0))
                    if not self._valid_ports(protocol, local_port, remote_port):
                        log.debug(
                            "Skipping endpoint with invalid ports local=%d remote=%d at physical 0x%X",
                            local_port,
                            remote_port,
                            physical_address,
                        )
                        continue
                    local = socket.inet_ntoa(struct.pack("<I", int(fields["LocalAddress"])))
                    remote = socket.inet_ntoa(struct.pack("<I", int(fields["RemoteAddress"])))
                except Exception:
                    log.debug("Skipping malformed address fields at physical 0x%X", physical_address)
                    continue

                dedupe_key = (protocol, local, local_port, remote, remote_port, pid)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                connections.append({
                    "Protocol": protocol,
                    "LocalAddress": local,
                    "LocalPort": local_port,
                    "RemoteAddress": remote,
                    "RemotePort": remote_port,
                    "OwningPID": pid,
                    "Status": "ACTIVE" if self.active_pids is None or pid in self.active_pids else "UNKNOWN",
                })
                log.info(
                    "NetScan found %s endpoint %s:%d -> %s:%d PID=%d",
                    protocol,
                    local,
                    local_port,
                    remote,
                    remote_port,
                    pid,
                )

        if not connections:
            log.warning("NetScan found no network endpoints in physical memory for signatures: %s", self.signatures)
        return connections

    @staticmethod
    def _valid_pid(pid: int) -> bool:
        return 0 < pid < MAX_PROCESS_ID

    @staticmethod
    def _valid_ports(protocol: str, local_port: int, remote_port: int) -> bool:
        if not (0 <= local_port <= 0xFFFF and 0 <= remote_port <= 0xFFFF):
            return False
        if protocol == "UDP":
            return local_port > 0
        return local_port > 0 or remote_port > 0


class PsScan(BasePlugin):
    """Scan raw physical memory for EPROCESS pool tags and validate carved processes."""

    DEFAULT_EPROCESS_LAYOUT: StructureLayout = {
        "UniqueProcessId": {"offset": 0x08, "format": "<Q"},
        "ActiveProcessLinks": {"offset": 0x10, "format": "<Q"},
        "ImageFileName": {"offset": 0x20, "format": "16s"},
    }
    DEFAULT_SIGNATURE = b"Proc"

    def __init__(
        self,
        signature: bytes = DEFAULT_SIGNATURE,
        layout: Optional[StructureLayout] = None,
        signature_offset: int = 0,
        max_candidates: int = 20000,
        max_scan_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        self.signature = signature
        self.layout = layout or self.DEFAULT_EPROCESS_LAYOUT
        self.signature_offset = signature_offset
        self.max_candidates = max_candidates
        self.max_scan_bytes = max_scan_bytes
        log.debug(
            "Initialized PsScan plugin with signature=%s signature_offset=0x%X layout=%s max_candidates=%d max_scan_bytes=%d",
            self.signature,
            self.signature_offset,
            self.layout,
            self.max_candidates,
            self.max_scan_bytes,
        )

    def run(self, context: MemoryContext) -> List[ProcessEntry]:
        scanner = PhysicalScanner(context.physical_layer)
        scan_end = min(context.physical_layer.size, self.max_scan_bytes)
        if scan_end < context.physical_layer.size:
            log.warning(
                "PsScan limiting scan to first 0x%X bytes of 0x%X-byte image",
                scan_end,
                context.physical_layer.size,
            )
        matches = scanner.scan(self.signature, end=scan_end, max_matches=self.max_candidates)
        entries: List[ProcessEntry] = []
        parser = StructureParser(context, self.layout)
        seen_physical: List[int] = []

        for match in matches:
            eprocess_phys = match - self.signature_offset
            if eprocess_phys in seen_physical or eprocess_phys < 0:
                continue
            seen_physical.append(eprocess_phys)

            try:
                fields = parser.parse_physical(eprocess_phys)
            except Exception as exc:
                log.debug("Failed to parse EPROCESS at physical 0x%X: %s", eprocess_phys, exc)
                continue

            pid = int(fields["UniqueProcessId"])
            name = str(fields["ImageFileName"])
            if self._validate(pid, name):
                entries.append(ProcessEntry(pid=pid, name=name, eprocess=eprocess_phys))
                log.info(
                    "PsScan carved process PID=%d Name=%s at physical EPROCESS=0x%X",
                    pid,
                    name,
                    eprocess_phys,
                )

        return entries

    @staticmethod
    def _validate(pid: int, name: str) -> bool:
        if pid <= 0 or pid > 0x100000:
            return False
        if not name or len(name) > 15:
            return False
        if any(ord(char) < 32 or ord(char) > 126 for char in name):
            return False
        return True


class MockProcessList(BasePlugin):
    """A plugin that reads a simple process structure from mock virtual memory."""

    STRUCT_FORMAT = "<I16s"
    ENTRY_SIZE = struct.calcsize(STRUCT_FORMAT)

    def __init__(self, virtual_addresses: Iterable[int]) -> None:
        self.virtual_addresses = list(virtual_addresses)
        log.debug("Initialized MockProcessList plugin with addresses: %s", self.virtual_addresses)

    def run(self, context: MemoryContext) -> List[ProcessEntry]:
        entries: List[ProcessEntry] = []
        for virtual_address in self.virtual_addresses:
            raw_data = context.read_virtual(virtual_address, self.ENTRY_SIZE)
            pid, raw_name = struct.unpack(self.STRUCT_FORMAT, raw_data)
            name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            entries.append(ProcessEntry(pid=pid, name=name, eprocess=virtual_address))
            log.info(
                "MockProcessList read PID=%d Name=%s from virtual address 0x%X",
                pid,
                name,
                virtual_address,
            )
        return entries


def create_demo_memory_file(path: Path) -> None:
    if not path.exists():
        path.write_bytes(b"\x00" * 0x1000)
