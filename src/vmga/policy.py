"""VMGA policy compatibility exports."""

from .vmga_adapter import ActionClass, ContentRisk, GmailAction, VMGAPolicy, load_vmga_policy

__all__ = [
    "ActionClass",
    "ContentRisk",
    "GmailAction",
    "VMGAPolicy",
    "load_vmga_policy",
]
