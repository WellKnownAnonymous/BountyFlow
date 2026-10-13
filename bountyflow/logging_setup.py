"""Logging setup."""
from __future__ import annotations

import logging
import sys

LOG = logging.getLogger("bountyflow")


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[bountyflow] %(message)s"))
    LOG.setLevel(level)
    LOG.handlers = [handler]
