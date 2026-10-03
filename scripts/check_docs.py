#!/usr/bin/env python3
"""Check the generated documentation site.

`docs/site/` is a build artifact, so most of what could go wrong there is caught
by rebuilding it. This script covers what a rebuild cannot see:

  1. every internal link resolves to a real page and a real anchor
  2. no page depends on the network — the site must work from file://
  3. every section has a heading, or the search index has nothing to title it
  4. the committed site is not stale relative to its Markdown sources
  5. the Markdown sources contain no obvious breakage (unclosed admonitions,
     a missing title, a page in the manifest that does not exist)

Usage: python3 scripts/check_docs.py
Exit code 0 means clean.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "docs" / "site"

sys.path.insert(0, str(ROOT / "scripts"))
from build_docs import PAGES  # noqa: E402  (path set up immediately above)

SECTION_ID_RE = re.compile(r'<section\b[^>]*\bid="([^"]+)"', re.I)
HREF_RE = re.compile(r'<a\b[^>]*\bhref="([^"]+)"', re.I)
HEADING_RE = re.compile(r"<h[1-3]\b", re.I)
# src= always loads a resource. href= only does so on <link>. An <a href> to an
# external standards document is a citation, which is encouraged, not a defect.
SRC_REMOTE_RE = re.compile(r'\bsrc\s*=\s*"(?:https?:)?//[^"]*"', re.I)
LINK_REMOTE_RE = re.compile(r'<link\b[^>]*\bhref\s*=\s*"(?:https?:)?//[^"]*"', re.I)
ALLOW_REMOTE = re.compile(r"xmlns|w3\.org", re.I)
ADMONITION_RE = re.compile(r"^(\s*)!!!\s+(\w+)", re.M)

#: The intro block before the first `##` has no heading of its own; the page's
#: <h1> sits directly above it.
HEADING_EXEMPT = {"overview"}


FENCE_RE = re.compile(r"^```.*?^```", re.S | re.M)


def check_sources() -> list[str]:
    problems: list[str] = []
    for page in PAGES:
        src = ROOT / page.src
        if not src.exists():
            problems.append(f"{page.src}: in the manifest but missing on disk")
            continue
        text = src.read_text(encoding="utf-8")
        if not text.lstrip().startswith("# "):
            problems.append(f"{page.src}: does not start with a single '# ' title")
        # Ignore fenced code: a `# comment` in a shell block is not a heading.
        prose = FENCE_RE.sub("", text)
        if re.search(r"^# ", prose.split("\n", 1)[1] if "\n" in prose else "", re.M):
            problems.append(f"{page.src}: contains a second '# ' heading; use '##'")
        # An admonition body must be indented, or it renders as a bare paragraph.
        lines = text.split("\n")
        for i, line in enumerate(lines):
            m = ADMONITION_RE.match(line)
            if not m:
                continue
            body = [l for l in lines[i + 1:i + 6] if l.strip()]
            if body and not body[0].startswith(" " * (len(m.group(1)) + 4)):
                problems.append(
                    f"{page.src}:{i + 1}: admonition body is not indented by 4 spaces")
    return problems


def main() -> int:
    problems = check_sources()

    pages = sorted(SITE.rglob("*.html"))
    if not pages:
        print(f"no pages under {SITE}; run python3 scripts/build_docs.py")
        return 1

    anchors: dict[Path, set[str]] = {}
    for page in pages:
        anchors[page] = set(SECTION_ID_RE.findall(page.read_text(encoding="utf-8")))

    for page in pages:
        rel = page.relative_to(ROOT)
        doc = page.read_text(encoding="utf-8")

        ids = SECTION_ID_RE.findall(doc)
        if not ids:
            problems.append(f"{rel}: no <section id=...> blocks; search index would be empty")
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            problems.append(f"{rel}: duplicate section id(s): {', '.join(dupes)}")
        for m in re.finditer(r"<section\b([^>]*)>(.*?)</section>", doc, re.S | re.I):
            attrs, inner = m.group(1), m.group(2)
            if any(f'id="{x}"' in attrs for x in HEADING_EXEMPT):
                continue
            if not HEADING_RE.search(inner):
                problems.append(f"{rel}: a <section> has no heading")
        if 'class="docsearch"' not in doc:
            problems.append(f"{rel}: missing the search box")

        for href in HREF_RE.findall(doc):
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target, _, frag = href.partition("#")
            resolved = page if not target else (page.parent / target).resolve()
            if not resolved.exists():
                problems.append(f"{rel}: broken link -> {href}")
            elif frag and resolved.suffix == ".html" and resolved in anchors:
                if frag not in anchors[resolved]:
                    problems.append(f"{rel}: link to missing anchor -> {href}")

        for pattern in (SRC_REMOTE_RE, LINK_REMOTE_RE):
            for m in pattern.finditer(doc):
                if not ALLOW_REMOTE.search(m.group(0)):
                    problems.append(
                        f"{rel}: remote resource breaks offline use -> {m.group(0)[:70]}")

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_docs.py"), "--check"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        problems.append((proc.stdout + proc.stderr).strip())

    print(f"checked {len(pages)} page(s), {sum(len(v) for v in anchors.values())} section(s), "
          f"{len(PAGES)} source page(s)")
    if problems:
        print(f"\n{len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
