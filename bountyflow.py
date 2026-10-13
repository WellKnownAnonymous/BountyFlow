#!/usr/bin/env python3
"""Backward-compat shim — use `python -m bountyflow` or the package."""
from bountyflow.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
