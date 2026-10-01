"""Observability package for audit logging."""
from .audit import log_event, AuditLogger

__all__ = ["log_event", "AuditLogger"]