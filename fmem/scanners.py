import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from .context import MemoryContext
from .layers import PhysicalLayer

log = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base class for memory scanning utilities."""

    @abstractmethod
    def scan(
        self,
        signature: bytes,
        start: int = 0,
        end: Optional[int] = None,
        max_matches: Optional[int] = None,
    ) -> List[int]:
        """Scan for a byte signature and return matching offsets."""
        raise NotImplementedError


class PhysicalScanner(BaseScanner):
    """Scan raw physical memory for byte signatures."""

    def __init__(self, physical_layer: PhysicalLayer, chunk_size: int = 50 * 1024 * 1024) -> None:
        self.physical_layer = physical_layer
        self.chunk_size = chunk_size

    def scan(
        self,
        signature: bytes,
        start: int = 0,
        end: Optional[int] = None,
        max_matches: Optional[int] = None,
    ) -> List[int]:
        if end is None:
            end = self.physical_layer.size
        if start < 0 or end > self.physical_layer.size:
            raise ValueError("Scan range is outside physical memory bounds")

        matches: List[int] = []
        offset = start
        overlap = max(len(signature) - 1, 0)

        while offset < end:
            read_size = min(self.chunk_size, end - offset)
            chunk = self.physical_layer.read_physical(offset, read_size)
            position = 0

            while True:
                found = chunk.find(signature, position)
                if found == -1:
                    break
                absolute = offset + found
                matches.append(absolute)
                if max_matches is not None and len(matches) >= max_matches:
                    log.warning(
                        "PhysicalScanner stopped after %d matches for signature %s",
                        max_matches,
                        signature,
                    )
                    return matches
                position = found + 1

            if read_size <= overlap:
                break
            offset += read_size - overlap

        log.debug(
            "PhysicalScanner found %d matches for signature %s in range 0x%X-0x%X",
            len(matches),
            signature,
            start,
            end,
        )
        return matches


class TranslationScanner(BaseScanner):
    """Scan a virtual address range for byte signatures using the translation layer."""

    def __init__(self, context: MemoryContext, page_size: int = 0x1000) -> None:
        self.context = context
        self.page_size = page_size

    def scan(
        self,
        signature: bytes,
        start: int = 0,
        end: Optional[int] = None,
        max_matches: Optional[int] = None,
    ) -> List[int]:
        if end is None:
            raise ValueError("Virtual end boundary must be specified for translation scans")

        matches: List[int] = []
        scan_address = start
        overlap = max(len(signature) - 1, 0)

        while scan_address < end:
            try:
                chunk = self.context.read_virtual(scan_address, self.page_size)
            except Exception:
                scan_address += self.page_size
                continue

            position = 0
            while True:
                found = chunk.find(signature, position)
                if found == -1:
                    break
                matches.append(scan_address + found)
                if max_matches is not None and len(matches) >= max_matches:
                    log.warning(
                        "TranslationScanner stopped after %d matches for signature %s",
                        max_matches,
                        signature,
                    )
                    return matches
                position = found + 1

            if self.page_size <= overlap:
                break
            scan_address += self.page_size - overlap

        log.debug(
            "TranslationScanner found %d matches for signature %s in virtual range 0x%X-0x%X",
            len(matches),
            signature,
            start,
            end,
        )
        return matches
