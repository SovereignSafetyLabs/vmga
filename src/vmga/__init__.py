"""VMGA (Vesta Mail Governance Adapter) - Gmail-specific governance extension.

This package provides email-domain-specific policy enforcement for agent runtimes,
building on the core Vesta Agent Runtime Governance framework.
"""

from .vmga_adapter import (
    VMGAGmailAdapter,
    VMGAPolicy,
    VMGAProposal,
    VMGAStateStore,
    GmailAction,
    ActionClass,
    ContentRisk,
    ApprovalRecord,
    load_vmga_policy,
)
from .backends import FakeGmailBackend
from .broker import VMGABroker
from .executor import VMGAExecutor
from .sqlite_state import SQLiteStateStore

__all__ = [
    "VMGAGmailAdapter",
    "VMGAPolicy", 
    "VMGAProposal",
    "VMGAStateStore",
    "GmailAction",
    "ActionClass",
    "ContentRisk",
    "ApprovalRecord",
    "FakeGmailBackend",
    "SQLiteStateStore",
    "VMGABroker",
    "VMGAExecutor",
    "load_vmga_policy",
]

__version__ = "0.2.0"
