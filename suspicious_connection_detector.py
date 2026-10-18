"""Backward-compatible entry point. Same as: python -m scd"""

import sys

from scd.cli import main

if __name__ == "__main__":
    sys.exit(main())
