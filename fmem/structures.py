import logging
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

from .context import MemoryContext
from .layers import PhysicalLayer, Windowsx64TranslationLayer
from .scanners import PhysicalScanner

log = logging.getLogger(__name__)


FieldLayout = Dict[str, Any]
StructureLayout = Dict[str, FieldLayout]


# Mock Windows structure layouts for Phase 4 demos.
EPROCESS_LAYOUT: StructureLayout = {
    "UniqueProcessId": {"offset": 0x08, "format": "<Q"},
    "ActiveProcessLinks": {"offset": 0x10, "format": "<Q"},
    "ImageFileName": {"offset": 0x20, "format": "16s"},
    "Peb": {"offset": 0x30, "format": "<Q"},
}

REAL_EPROCESS_LAYOUT: StructureLayout = {
    "UniqueProcessId": {"offset": 0x440, "format": "<Q"},
    "ActiveProcessLinks": {"offset": 0x448, "format": "<Q"},
    "ImageFileName": {"offset": 0x5A8, "format": "16s"},
    "DirectoryTableBase": {"offset": 0x028, "format": "<Q"},
}

REAL_IMAGE_FILENAME_OFFSET = 0x5A8
REAL_DIRECTORY_TABLE_BASE_OFFSET = 0x028
REAL_SYSTEM_PROCESS_NAME = b"System\x00"

PEB_LAYOUT: StructureLayout = {
    "Ldr": {"offset": 0x18, "format": "<Q"},
}

PEB_LDR_DATA_LAYOUT: StructureLayout = {
    "InLoadOrderModuleList": {"offset": 0x10, "format": "<Q"},
}

LDR_DATA_TABLE_ENTRY_LAYOUT: StructureLayout = {
    "InLoadOrderLinks": {"offset": 0x0, "format": "<Q"},
    "DllBase": {"offset": 0x08, "format": "<Q"},
    "SizeOfImage": {"offset": 0x10, "format": "<I"},
    "BaseDllName": {"offset": 0x14, "format": "16s"},
}

NETWORK_ENDPOINT_LAYOUT: StructureLayout = {
    "LocalAddress": {"offset": 0x04, "format": "<I"},
    "RemoteAddress": {"offset": 0x08, "format": "<I"},
    "LocalPort": {"offset": 0x0C, "format": "<H"},
    "RemotePort": {"offset": 0x0E, "format": "<H"},
    "OwningPID": {"offset": 0x10, "format": "<I"},
}


class StructureParser:
    """Dynamically parse a kernel structure based on a field layout definition."""

    def __init__(self, context: MemoryContext, layout: StructureLayout) -> None:
        self.context = context
        self.layout = layout
        log.debug("Initialized StructureParser with layout: %s", layout)

    def parse(self, virtual_address: int) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for field_name, field_spec in self.layout.items():
            offset = field_spec["offset"]
            fmt = field_spec["format"]
            size = struct.calcsize(fmt)
            raw_bytes = self.context.read_virtual(virtual_address + offset, size)
            values[field_name] = self._decode_field(field_name, virtual_address + offset, raw_bytes)
        return values

    def parse_physical(self, physical_address: int) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for field_name, field_spec in self.layout.items():
            offset = field_spec["offset"]
            fmt = field_spec["format"]
            size = struct.calcsize(fmt)
            raw_bytes = self.context.physical_layer.read_physical(physical_address + offset, size)
            values[field_name] = self._decode_field(field_name, physical_address + offset, raw_bytes, physical=True)
        return values

    def field_offset(self, field_name: str) -> int:
        return int(self.layout[field_name]["offset"])

    def parse_field(self, virtual_address: int, field_name: str) -> Any:
        return self.parse(virtual_address)[field_name]

    def _decode_field(
        self,
        field_name: str,
        offset: int,
        raw_bytes: bytes,
        physical: bool = False,
    ) -> Any:
        fmt = self.layout[field_name]["format"]
        decoded = struct.unpack(fmt, raw_bytes)
        value = decoded[0] if len(decoded) == 1 else decoded
        if isinstance(value, bytes):
            value = value.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        log.debug(
            "Parsed field %s at %s offset 0x%X: %s",
            field_name,
            "physical" if physical else "virtual",
            offset,
            value,
        )
        return value

    def parse_field(self, virtual_address: int, field_name: str) -> Any:
        return self.parse(virtual_address)[field_name]


class CR3Detector:
    """Detect candidate CR3 values by attempting one or more virtual translations."""

    def __init__(
        self,
        physical_layer: PhysicalLayer,
        verification_virtual_addresses: Optional[List[int]] = None,
    ) -> None:
        self.physical_layer = physical_layer
        self.verification_virtual_addresses = (
            verification_virtual_addresses or [0xFFFFF80000000000]
        )

    def find_candidates(self, max_pages: int = 0x1000) -> List[int]:
        candidates: List[int] = []
        total_pages = min(max_pages, self.physical_layer.size // Windowsx64TranslationLayer.PAGE_SIZE)

        for page_index in range(total_pages):
            candidate_cr3 = page_index * Windowsx64TranslationLayer.PAGE_SIZE
            try:
                pml4_entry = int.from_bytes(
                    self.physical_layer.read_physical(candidate_cr3, 8),
                    "little",
                )
            except Exception:
                continue

            if not (pml4_entry & 0x1):
                continue

            log.debug("Candidate CR3 page at 0x%X has a present PML4 entry", candidate_cr3)

            if self._valid_cr3_candidate(candidate_cr3):
                candidates.append(candidate_cr3)
                log.debug(
                    "Validated CR3 candidate 0x%X against addresses %s",
                    candidate_cr3,
                    self.verification_virtual_addresses,
                )

        return candidates

    def find_system_eprocess_physical(self, process_name: bytes = REAL_SYSTEM_PROCESS_NAME) -> Optional[int]:
        scanner = PhysicalScanner(self.physical_layer)
        matches = scanner.scan(process_name)

        for match in matches:
            candidate_eprocess = match - REAL_IMAGE_FILENAME_OFFSET
            if candidate_eprocess < 0 or candidate_eprocess + REAL_IMAGE_FILENAME_OFFSET >= self.physical_layer.size:
                continue

            try:
                fake_context = MemoryContext(self.physical_layer, None)  # translation not needed for raw physical parsing
                parser = StructureParser(fake_context, REAL_EPROCESS_LAYOUT)
                fields = parser.parse_physical(candidate_eprocess)
            except Exception as exc:
                log.debug(
                    "Failed to validate System EPROCESS at physical 0x%X: %s",
                    candidate_eprocess,
                    exc,
                )
                continue

            if fields["ImageFileName"] != process_name.rstrip(b"\x00").decode():
                continue

            unique_pid = int(fields["UniqueProcessId"])
            if unique_pid != 4:
                log.debug(
                    "Skipping false positive System block with invalid PID %d at physical 0x%X",
                    unique_pid,
                    candidate_eprocess,
                )
                continue

            dtb_value = int.from_bytes(
                self.physical_layer.read_physical(
                    candidate_eprocess + REAL_DIRECTORY_TABLE_BASE_OFFSET,
                    8,
                ),
                "little",
            )
            if dtb_value == 0 or dtb_value == 0xFFFFFFFFFFFFFFFF:
                log.debug(
                    "Skipping System EPROCESS false positive at 0x%X with invalid DTB 0x%X",
                    candidate_eprocess,
                    dtb_value,
                )
                continue
            if dtb_value >= self.physical_layer.size:
                log.debug(
                    "Skipping System EPROCESS false positive at 0x%X with out-of-range DTB 0x%X",
                    candidate_eprocess,
                    dtb_value,
                )
                continue

            log.debug("Found System EPROCESS at physical 0x%X with valid DTB 0x%X", candidate_eprocess, dtb_value)
            return candidate_eprocess

        log.debug("No System EPROCESS was found in physical memory")
        return None

    def find_cr3_from_system_process(self, process_name: bytes = REAL_SYSTEM_PROCESS_NAME) -> Optional[int]:
        scanner = PhysicalScanner(self.physical_layer)
        matches = scanner.scan(process_name)

        for match in matches:
            candidate_eprocess = match - REAL_IMAGE_FILENAME_OFFSET
            if candidate_eprocess < 0 or candidate_eprocess + REAL_IMAGE_FILENAME_OFFSET >= self.physical_layer.size:
                continue

            try:
                fake_context = MemoryContext(self.physical_layer, None)
                parser = StructureParser(fake_context, REAL_EPROCESS_LAYOUT)
                fields = parser.parse_physical(candidate_eprocess)
            except Exception as exc:
                log.debug(
                    "Failed to validate System EPROCESS at physical 0x%X: %s",
                    candidate_eprocess,
                    exc,
                )
                continue

            if fields["ImageFileName"] != process_name.rstrip(b"\x00").decode():
                continue

            log.debug("Found System EPROCESS at physical 0x%X", candidate_eprocess)
            return candidate_eprocess

        log.debug("No System EPROCESS was found in physical memory")
        return None

    def find_cr3_from_system_process(self, process_name: bytes = REAL_SYSTEM_PROCESS_NAME) -> Optional[int]:
        system_eprocess = self.find_system_eprocess_physical(process_name)
        if system_eprocess is None:
            log.debug("No System process CR3 candidate was found in physical memory")
            return None

        dtb_value = int.from_bytes(
            self.physical_layer.read_physical(system_eprocess + REAL_DIRECTORY_TABLE_BASE_OFFSET, 8),
            "little",
        )
        cr3 = self._normalize_cr3(dtb_value)
        if self._is_valid_cr3_value(cr3):
            log.debug(
                "Detected CR3 0x%X from System EPROCESS at physical 0x%X",
                cr3,
                system_eprocess,
            )
            return cr3

        log.debug(
            "System EPROCESS at physical 0x%X had an invalid DTB value 0x%X",
            system_eprocess,
            dtb_value,
        )
        return None

    def discover_profile(self) -> str:
        if self.find_cr3_from_system_process() is not None:
            log.debug("Discovered profile 'win10' from memory image")
            return "win10"
        log.debug("Defaulting profile to 'mock' after profile discovery heuristics")
        return "mock"

    def autodetect_cr3(self, max_pages: int = 0x1000) -> Optional[int]:
        system_cr3 = self.find_cr3_from_system_process()
        if system_cr3 is not None:
            return system_cr3

        candidates = self.find_candidates(max_pages)
        if not candidates:
            log.warning("No CR3 candidates were detected")
            return None
        if len(candidates) > 1:
            log.warning("Multiple CR3 candidates detected; choosing the first one: %s", candidates)
        return candidates[0]

    def _normalize_cr3(self, cr3_value: int) -> int:
        return cr3_value & ~0xFFF

    def _valid_cr3_candidate(self, candidate_cr3: int) -> bool:
        for virtual_address in self.verification_virtual_addresses:
            try:
                walker = Windowsx64TranslationLayer(self.physical_layer, candidate_cr3)
                physical = walker.translate_address(virtual_address)
                if 0 <= physical < self.physical_layer.size:
                    return True
            except Exception as exc:
                log.debug(
                    "CR3 candidate 0x%X failed verification for 0x%X: %s",
                    candidate_cr3,
                    virtual_address,
                    exc,
                )
        return False

    def _is_valid_cr3_value(self, cr3_value: int) -> bool:
        if cr3_value <= 0 or cr3_value % Windowsx64TranslationLayer.PAGE_SIZE != 0:
            return False
        if cr3_value >= self.physical_layer.size:
            return False
        return True
