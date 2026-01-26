"""Package entry point for python -m bannedfuncdetector."""

import sys

from .bannedfunc import main


if __name__ == "__main__":
    sys.exit(main())
