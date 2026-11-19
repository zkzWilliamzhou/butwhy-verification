"""python -m butwhy entry point."""
from __future__ import annotations

import sys
from typing import List, Optional

from . import cli


def main(argv: Optional[List[str]] = None) -> int:
    return cli.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
