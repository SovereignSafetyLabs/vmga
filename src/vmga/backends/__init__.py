"""VMGA Gmail backend implementations."""

from .fake_gmail import FakeGmailBackend
from .gogcli import GogCLIBackend

__all__ = ["FakeGmailBackend", "GogCLIBackend"]
