#!/usr/bin/env python3
"""Regenerate safelist-dx-auth.html from the dx-auth login pages.

Tailwind's @source scanner cannot see classes inside a git dependency in
~/.cargo, so every string token the two pages use is listed in a file the
scanner can read. Run `just safelist` after moving the dx-auth pin.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = ["src/login_page.rs", "src/local_login_page.rs"]


def checkout() -> pathlib.Path:
    """The dx-auth source cargo resolved for this Cargo.lock."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    # --no-deps omits dependency paths; find the checkout by the locked tag instead.
    lock = (ROOT / "Cargo.lock").read_text()
    m = re.search(r'name = "dx-auth"\nversion = "([^"]+)"\nsource = "git\+[^#"]+#([0-9a-f]+)"', lock)
    if not m:
        sys.exit("dx-auth is not a git dependency in Cargo.lock")
    version, rev = m.groups()
    for candidate in (pathlib.Path.home() / ".cargo/git/checkouts").glob("dx-kit-*/*/crates/dx-auth"):
        if candidate.parent.parent.name.startswith(rev[:7]):
            return candidate, version
    sys.exit(f"no cargo checkout for dx-auth {version} ({rev[:7]}); run `cargo fetch` first")


def main() -> None:
    src_dir, version = checkout()
    string_literal = re.compile(r'"((?:[^"\\]|\\.)*)"')
    classish = re.compile(r"[A-Za-z0-9_:\-\./\[\]#%!]+")
    tokens = set()
    for page in PAGES:
        for lit in string_literal.findall((src_dir / page).read_text()):
            for t in lit.split():
                if classish.fullmatch(t) and any(c.isalpha() for c in t) and "://" not in t:
                    tokens.add(t)
    header = (
        f"<!--\n  dx-auth LoginPage + LocalLoginPage safelist (dx-auth v{version}).\n\n"
        "  Tailwind's @source scanner cannot see classes inside a git dependency in\n"
        "  ~/.cargo, so every string token the two login pages use is listed here and\n"
        "  this file is an @source in tailwind.css. Regenerate with `just safelist`\n"
        "  whenever the dx-auth pin moves.\n-->\n"
    )
    (ROOT / "safelist-dx-auth.html").write_text(header + '<div class="' + " ".join(sorted(tokens)) + '"></div>\n')
    print(f"wrote safelist-dx-auth.html with {len(tokens)} tokens from dx-auth v{version}")


if __name__ == "__main__":
    main()
