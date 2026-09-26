"""
Logging for SecureMailScope.

A single handler is attached to the ``securemailscope`` package logger and
writes to stderr (never stdout, which the CLI uses for results). Module loggers
propagate to it, so one ``setLevel`` call controls the whole package.

A file log is written only when ``SMS_LOG_FILE`` is set. Nothing is created on
import. Log messages never contain payload bytes or credentials: modules log
counts, hashes, and identifiers only.
"""
import logging
import os
import sys

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-32s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_ROOT = "securemailscope"
_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger(_ROOT)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        root.addHandler(handler)
        log_file = os.environ.get("SMS_LOG_FILE")
        if log_file:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
            root.addHandler(fh)
        root.setLevel(os.environ.get("SMS_LOG_LEVEL", "INFO").upper())
        root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger that propagates to the package handler."""
    _configure()
    if not name.startswith(_ROOT):
        name = f"{_ROOT}.{name}"
    return logging.getLogger(name)
