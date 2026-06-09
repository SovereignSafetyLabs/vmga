"""State store compatibility exports."""

from .vmga_adapter import VMGAStateStore

JSONStateStore = VMGAStateStore

__all__ = ["JSONStateStore", "VMGAStateStore"]
