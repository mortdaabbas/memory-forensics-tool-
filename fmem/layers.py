import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict

log = logging.getLogger(__name__)


class PhysicalLayer:
    """Represents the raw physical memory file layer.

    This layer is responsible for safely opening a binary memory dump and
    reading bytes by physical offset. It is intentionally minimal so that
    higher layers can remain agnostic to file handling details.
    """

    def __init__(self, image_path: Path) -> None:
        self.image_path = image_path
        self._file = image_path.open("rb")
        self._size = self._file.seek(0, 2)
        self._file.seek(0)
        log.debug("Initialized PhysicalLayer for '%s' with size %d", image_path, self._size)

    def read_physical(self, offset: int, size: int) -> bytes:
        """Read raw bytes from a physical offset in the memory image."""
        if offset < 0:
            raise ValueError("Offset must be non-negative")
        if size < 0:
            raise ValueError("Size must be non-negative")
        if offset + size > self._size:
            raise ValueError(
                "Requested range is outside the bounds of the physical memory image"
            )

        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) != size:
            raise IOError("Failed to read the requested number of bytes")
        log.debug("Read %d bytes from physical offset 0x%X", size, offset)
        return data

    @property
    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self._file.close()
        log.debug("Closed PhysicalLayer file handle")

    def __enter__(self) -> "PhysicalLayer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class TranslationLayer(ABC):
    """Abstract base class for virtual-to-physical address translation.

    Concrete implementations must provide the translation logic. This decouples
    page table walking or other translation strategies from the rest of the
    framework.
    """

    @abstractmethod
    def translate_address(self, virtual_address: int) -> int:
        """Translate a virtual address into a physical file offset."""
        raise NotImplementedError


class MockTranslationLayer(TranslationLayer):
    """A simple translation layer for testing and early development.

    This uses a hardcoded mapping so that the framework can be validated before
    a real x64 page walker is implemented.
    """

    def __init__(self, mapping: Dict[int, int]) -> None:
        self.mapping = mapping
        log.debug("Initialized MockTranslationLayer with mapping: %s", mapping)

    def translate_address(self, virtual_address: int) -> int:
        physical = self.mapping.get(virtual_address)
        if physical is None:
            raise KeyError(f"Virtual address 0x{virtual_address:X} is not mapped")
        log.debug(
            "Translated virtual address 0x%X to physical offset 0x%X",
            virtual_address,
            physical,
        )
        return physical


class Windowsx64TranslationLayer(TranslationLayer):
    """Translate Windows x64 virtual addresses via a 4-level page table walker.

    This implementation reads page table entries from the raw physical image
    and supports 4KB pages plus 2MB and 1GB large pages.
    """

    PAGE_SIZE = 0x1000
    PAGE_SHIFT = 12
    PAGE_OFFSET_MASK = PAGE_SIZE - 1
    ENTRY_SIZE = 8
    INDEX_MASK = 0x1FF
    MASK_4KB = 0x000FFFFFFFFFF000
    MASK_2MB = 0x000FFFFFFFE00000
    MASK_1GB = 0x000FFFFFC0000000
    CR3_MASK = ~(PAGE_SIZE - 1)

    def __init__(self, physical_layer: PhysicalLayer, cr3: int) -> None:
        self.physical_layer = physical_layer
        self.cr3 = cr3 & self.CR3_MASK
        if self.cr3 != cr3:
            log.debug("Normalized CR3 from 0x%X to page-aligned 0x%X", cr3, self.cr3)
        log.debug("Initialized Windowsx64TranslationLayer with CR3=0x%X", self.cr3)

    def translate_address(self, virtual_address: int) -> int:
        if virtual_address < 0:
            raise ValueError("Virtual address must be non-negative")
        if not self._is_canonical(virtual_address):
            raise ValueError(f"Virtual address 0x{virtual_address:X} is not canonical")

        pml4_index = (virtual_address >> 39) & self.INDEX_MASK
        pdpt_index = (virtual_address >> 30) & self.INDEX_MASK
        pd_index = (virtual_address >> 21) & self.INDEX_MASK
        pt_index = (virtual_address >> 12) & self.INDEX_MASK
        page_offset = virtual_address & self.PAGE_OFFSET_MASK

        pml4_entry = self._read_entry(self.cr3, pml4_index, "PML4")
        self._assert_present(pml4_entry, "PML4")
        pdpt_base = self._entry_base(pml4_entry)

        pdpt_entry = self._read_entry(pdpt_base, pdpt_index, "PDPT")
        self._assert_present(pdpt_entry, "PDPT")
        if self._is_page_size(pdpt_entry):
            physical_base = pdpt_entry & self.MASK_1GB
            offset = virtual_address & ((1 << 30) - 1)
            return physical_base + offset

        pd_base = self._entry_base(pdpt_entry)
        pd_entry = self._read_entry(pd_base, pd_index, "PD")
        self._assert_present(pd_entry, "PD")
        if self._is_page_size(pd_entry):
            physical_base = pd_entry & self.MASK_2MB
            offset = virtual_address & ((1 << 21) - 1)
            return physical_base + offset

        pt_base = self._entry_base(pd_entry)
        pt_entry = self._read_entry(pt_base, pt_index, "PT")
        self._assert_present(pt_entry, "PT")

        physical_base = pt_entry & self.MASK_4KB
        return physical_base + page_offset

    def _read_entry(self, table_base: int, index: int, level_name: str) -> int:
        entry_offset = table_base + (index << 3)
        raw_entry = self.physical_layer.read_physical(entry_offset, self.ENTRY_SIZE)
        entry = int.from_bytes(raw_entry, "little")
        log.debug(
            "%s entry[%d] at 0x%X = 0x%016X",
            level_name,
            index,
            entry_offset,
            entry,
        )
        return entry

    def _assert_present(self, entry: int, level_name: str) -> None:
        if not self._is_present(entry):
            raise KeyError(f"{level_name} entry is not present")

    @staticmethod
    def _is_present(entry: int) -> bool:
        return bool(entry & 0x1)

    @staticmethod
    def _is_page_size(entry: int) -> bool:
        return bool(entry & (1 << 7))

    @staticmethod
    def _is_canonical(virtual_address: int) -> bool:
        if virtual_address < (1 << 47):
            return True
        return virtual_address >= (1 << 64) - (1 << 47)

    @staticmethod
    def _entry_base(entry: int) -> int:
        return entry & Windowsx64TranslationLayer.MASK_4KB
