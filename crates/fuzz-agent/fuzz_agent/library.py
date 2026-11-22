"""The copy of p14g's repository that the agent reads, mounted read-only at `/library` in its sandbox.

The checkout itself is not mounted: it has `.env`, the virtual environment and the runs of this fuzzer in it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

PATH = ROOT / 'crates' / 'fuzz-agent' / '.library'
"""Where the copy is kept, ignored by git. It exists from import, since the agent's mount opens it then."""
PATH.mkdir(exist_ok=True)


def files() -> list[str]:
    """Files the agent may read: those git tracks or would track, so nothing ignored and nothing outside."""
    listed = subprocess.run(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    # `resolve` follows a symlink, which must not lead out of the checkout
    return [
        name
        for name in listed.stdout.splitlines()
        if (ROOT / name).is_file() and (ROOT / name).resolve().is_relative_to(ROOT)
    ]


def refresh() -> None:
    """Replace the copy with the files of the checkout as they are now, so each run reads the current code.

    `PATH` is emptied rather than removed, since the mount holds the directory itself open.
    """
    for child in PATH.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    for name in files():
        target = PATH / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
