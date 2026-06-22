import logging
from dataclasses import dataclass

from .layers import PhysicalLayer, TranslationLayer

log = logging.getLogger(__name__)


@dataclass
class MemoryContext:
    """Context manager tying physical and translation layers together."""

    physical_layer: PhysicalLayer
    translation_layer: TranslationLayer

    def read_virtual(self, virtual_address: int, size: int) -> bytes:
        """Read raw memory bytes from a virtual address.

        The virtual address is translated to a physical offset before the raw
        bytes are fetched from the physical memory image.
        """
        log.debug(
            "Reading %d bytes from virtual address 0x%X",
            size,
            virtual_address,
        )
        physical_offset = self.translation_layer.translate_address(virtual_address)
        data = self.physical_layer.read_physical(physical_offset, size)
        log.debug(
            "Fetched %d bytes from virtual offset 0x%X for virtual address 0x%X",
            size,
            physical_offset,
            virtual_address,
        )
        return data
