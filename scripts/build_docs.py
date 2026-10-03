#!/usr/bin/env python3
"""Build the Attest documentation site from Markdown.

WHY THIS EXISTS
---------------
The pages under `docs/site/` are self-contained: no server, no runtime
dependencies, no CDN. You can open them from a local folder, email one to
somebody, or read them ten years from now. That property is worth keeping.

Hand-writing that HTML, however, means the site and the Markdown would be two
copies of the same facts, and two copies drift. So instead:

    docs/src/*.md, docs/*.md, lab/**/*.md    <-- the single source of truth
              |
              |  scripts/build_docs.py
              v
    docs/site/*.html                          <-- a COMMITTED build artifact

The output is committed on purpose, so reading the documentation never requires
running anything. `--check` rebuilds in memory and fails if the committed
output differs, which is what stops the artifact from going stale.

USAGE
    python3 scripts/build_docs.py            # write docs/site/
    python3 scripts/build_docs.py --check    # exit 1 if the committed site is stale
    python3 scripts/build_docs.py --force    # accepted, output is always overwritten

Mermaid diagrams are pre-rendered to inline SVG by `scripts/render_diagrams.mjs`
(see `docs/site/diagrams/`). If that has not been run, the builder falls back to
showing the diagram source rather than failing the build.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import markdown
from markdown.extensions.toc import slugify

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "docs" / "site"
DIAGRAMS = SITE / "diagrams"
LAB_RESULTS = ROOT / "lab" / "keycloak" / "SPIKE-3-RESULTS.md"


# --------------------------------------------------------------------------
# The site manifest. Order here is reading order, and drives the nav and the
# previous/next links. To add a page: write the Markdown, add one entry.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Page:
    slug: str
    src: str
    group: str
    title: str
    blurb: str = ""
    toc: bool = True


PAGES: list[Page] = [
    # --- Guide: written for a human who is new to all of this ---------------
    Page("index", "docs/src/index.md", "Guide", "Start here",
         "What Attest is, where the project stands, and how to read these pages."),
    Page("problem", "docs/src/problem.md", "Guide", "The problem it removes",
         "Why passwords fail, and why most multi-factor authentication does not fix it."),
    Page("zero-trust", "docs/src/zero-trust.md", "Guide", "The big picture",
         "What Zero Trust means here, the three planes, and the boundaries we treat as hostile."),
    Page("passwordless", "docs/src/passwordless.md", "Guide", "Sign-in, end to end",
         "How a passkey ceremony works, and how we require genuine hardware keys."),
    Page("sessions", "docs/src/sessions.md", "Guide", "After sign-in",
         "Token binding, per-request policy, keeping tenants apart, and revocation."),
    Page("recovery", "docs/src/recovery.md", "Guide", "Recovery, the weak link",
         "Where attackers go once the front door is locked."),
    Page("operating", "docs/src/operating.md", "Guide", "Running the identity provider",
         "The operational burden we took on, and why we took it on anyway."),
    Page("limits", "docs/src/limits.md", "Guide", "Limits and non-goals",
         "What this deliberately does not do, and the risks we accept."),

    # --- Evidence: the part that separates design from wishful thinking -----
    Page("evidence", "EVIDENCE.md", "Evidence", "Evidence register",
         "Every load-bearing claim, how it is evidenced, and where confidence is less than total."),
    Page("verification", "docs/src/verification.md", "Evidence", "What we tested",
         "The verification spikes: what was actually run, what passed, and what is still open."),
    Page("decisions", "docs/src/decisions-guide.md", "Evidence", "Decisions and why",
         "Each significant choice, the alternatives rejected, and what it costs."),

    # --- Reference: the engineering documents, rendered from source ---------
    Page("plan", "docs/PLAN.md", "Reference", "Architecture and plan",
         "Phases, acceptance criteria, cost drivers and the risk register."),
    Page("identity", "docs/identity-and-passkeys.md", "Reference", "Identity in detail",
         "Realm configuration, exact WebAuthn policy settings, enrolment and recovery."),
    Page("authorization", "docs/authorization-and-sessions.md", "Reference", "Sessions and authorization",
         "Token binding, the policy engine, revocation and machine identity."),
    Page("threat-model", "docs/threat-model.md", "Reference", "Threat model",
         "Every attack considered, its outcome, and the risks accepted deliberately."),
    Page("adr", "docs/decisions.md", "Reference", "Decision register",
         "Formal records, open questions and the verification item list."),
    Page("lab-results", str(LAB_RESULTS.relative_to(ROOT)), "Reference", "Lab results: hardware keys",
         "The Spike #3 experiment, reproducible step by step."),
    Page("lab-results-dpop", "lab/keycloak/SPIKE-1-RESULTS.md", "Reference", "Lab results: token binding",
         "The Spike #1 experiment: DPoP enforcement, and the traps that would cost real time."),
    Page("lab-results-browser", "lab/browser/SPIKE-4-RESULTS.md", "Reference", "Lab results: browser keys",
         "The S4 experiment: does a browser keep the session key after a restart?"),
    Page("lab-results-browsers", "lab/browser/SPIKE-4b-RESULTS.md", "Reference", "Lab results: other browsers",
         "The S4b experiment: three Chromium browsers pass; Firefox and Safari remain manual."),
    Page("lab-results-stepup", "lab/keycloak/SPIKE-5b-RESULTS.md", "Reference", "Lab results: step-up rejected",
         "How a failed experiment uncovered a live, unmitigated CVE in the component the design depended on."),
]

#: Source path (relative to repo root, POSIX) -> output slug. Used to rewrite
#: relative links in the Markdown so they point at the right page.
LINK_MAP: dict[str, str] = {}
for _p in PAGES:
    LINK_MAP[Path(_p.src).as_posix()] = _p.slug
LINK_MAP["./SPIKE-3-RESULTS.md"] = "lab-results"  # referenced from within lab/
SLUGS = {p.slug for p in PAGES}


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


# --------------------------------------------------------------------------
# Markdown -> HTML
# --------------------------------------------------------------------------
MERMAID_RE = re.compile(r"```mermaid\n(.*?)```", re.S)
FENCE_RE = re.compile(r"^(`{3,}|~{3,})", re.M)

MD_EXTENSIONS = [
    "extra",           # tables, fenced_code, attr_list, def_list, abbr, footnotes
    "admonition",
    "codehilite",
    "md_in_html",
    "sane_lists",
    "smarty",
    "toc",
]

MD_CONFIG = {
    "codehilite": {"css_class": "codehilite", "guess_lang": False, "linenums": False},
    "toc": {"permalink": False, "slugify": lambda v, s: slugify(v, "-")},
}


def diagram_slug(code: str) -> str:
    """Stable, unique name for a diagram, shared with tools/render_diagrams.mjs.

    Includes a content hash on purpose. Keying on the first line alone (e.g.
    "sequenceDiagram") collides, and the collision is silent: one diagram simply
    overwrites another. The hash also means a changed diagram gets a new file
    rather than serving a stale render.

    Deliberately simpler than Markdown's own slugify so Python and JavaScript
    produce byte-identical results.
    """
    body = code.strip()
    first = body.splitlines()[0] if body else "diagram"
    base = re.sub(r"[^a-z0-9]+", "-", first.strip().lower()).strip("-")[:40]
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:8]
    return f"{base}-{digest}"


def diagram_figure(name: str) -> str | None:
    """A pre-rendered diagram as inline SVG, in both palettes.

    Two variants are embedded because Mermaid bakes colours into the SVG, and
    CSS cannot re-theme it. The stylesheet shows whichever matches the active
    theme.
    """
    dark = DIAGRAMS / f"{name}-dark.svg"
    light = DIAGRAMS / f"{name}-light.svg"
    if not (dark.exists() and light.exists()):
        return None
    return (
        '<figure class="diagram">'
        f'<div class="dg dg-dark">{dark.read_text(encoding="utf-8")}</div>'
        f'<div class="dg dg-light">{light.read_text(encoding="utf-8")}</div>'
        "</figure>"
    )


def replace_mermaid(text: str, source: str) -> tuple[str, list[str]]:
    """Swap ```mermaid fences for pre-rendered SVG.

    Missing renders degrade to a visible note rather than a broken build, so the
    documentation stays buildable without the (heavy) diagram toolchain.
    """
    missing: list[str] = []

    def sub(match: re.Match[str]) -> str:
        body = match.group(1).strip()
        name = diagram_slug(body)
        figure = diagram_figure(name)
        if figure:
            return figure
        missing.append(name)
        return (
            '<figure class="diagram diagram-missing">'
            "<figcaption>Diagram not pre-rendered. "
            "Run <code>node tools/render_diagrams.mjs</code>.</figcaption>"
            f"<pre><code>{html.escape(body)}</code></pre></figure>"
        )

    return MERMAID_RE.sub(sub, text), missing


def rewrite_links(rendered: str, source_path: Path,
                  unresolved: list[str] | None = None) -> str:
    """Point relative Markdown links at the generated HTML pages.

    Resolves in two passes. First as a real path relative to the source file,
    which is what an ordinary `[x](../PLAN.md)` needs. If that fails, as a
    *logical page name* — so a page can also link `[the plan](plan.md)` without
    the author having to know where the file lives or how deep the page sits.

    A resolvable-looking Markdown link that matches nothing is recorded rather
    than silently left alone: it would otherwise survive into the built site as
    a 404 that nothing reports.
    """
    src_dir = source_path.parent

    def sub(match: re.Match[str]) -> str:
        href = match.group(1)
        if href.startswith(("http://", "https://", "mailto:", "#")):
            return match.group(0)
        target, _, frag = href.partition("#")
        if not target:
            return match.group(0)

        slug = None
        try:
            slug = LINK_MAP.get(rel((src_dir / target).resolve()))
        except ValueError:
            slug = None
        if slug is None:
            stem = Path(target).stem
            if stem in SLUGS:
                slug = stem
        if slug is None:
            if target.endswith(".md") and unresolved is not None:
                unresolved.append(
                    f"{rel(source_path)}: link to '{target}' matches no page "
                    f"(known slugs: {', '.join(sorted(SLUGS))})")
            return match.group(0)

        out = slug + ".html"
        if frag:
            out += "#" + frag
        return f'href="{out}"'

    return re.sub(r'href="([^"]+)"', sub, rendered)


def wrap_sections(rendered: str) -> tuple[str, list[dict]]:
    """Wrap top-level `<h2>` chunks in `<section id>` blocks.

    Sections are what the search index, the on-this-page nav and the anchors all
    key off, so they are structural rather than cosmetic.
    """
    heading_re = re.compile(r'<h2\b([^>]*)>(.*?)</h2>', re.S)
    marks = list(heading_re.finditer(rendered))
    if not marks:
        body = rendered
        return f'<section id="page">{body}</section>', []

    sections: list[dict] = []
    out: list[str] = []
    # Anything before the first h2 (intro prose) becomes its own section.
    intro = rendered[: marks[0].start()].strip()
    if intro:
        out.append(f'<section id="overview">{intro}</section>')
        sections.append({"id": "overview", "title": "Overview", "level": 1})

    for i, m in enumerate(marks):
        attrs, inner = m.group(1), m.group(2)
        end = marks[i + 1].start() if i + 1 < len(marks) else len(rendered)
        chunk = rendered[m.end():end]
        idm = re.search(r'id="([^"]+)"', attrs)
        sec_id = idm.group(1) if idm else f"section-{i + 1}"
        plain = re.sub(r"<[^>]+>", "", inner)
        title = html.unescape(plain).strip()
        sections.append({"id": sec_id, "title": title, "level": 2})
        out.append(
            f'<section id="{sec_id}">'
            f"<h2>{inner}</h2>{chunk}"
            f"</section>"
        )
    return "\n".join(out), sections


def split_toc(rendered: str) -> list[dict]:
    """h2/h3 outline for the on-this-page navigation."""
    out: list[dict] = []
    for m in re.finditer(r'<h([23])\b[^>]*id="([^"]+)"[^>]*>(.*?)</h\1>', rendered, re.S):
        level, anchor, inner = int(m.group(1)), m.group(2), m.group(3)
        title = html.unescape(re.sub(r"<[^>]+>", "", inner)).strip()
        out.append({"level": level, "id": anchor, "title": title})
    return out


# --------------------------------------------------------------------------
# Page template
# --------------------------------------------------------------------------
def site_css() -> str:
    return (ROOT / "docs" / "site" / "docs.css").read_text(encoding="utf-8")


NAV_GROUPS = ["Guide", "Evidence", "Reference"]


def render_nav(current: Page) -> str:
    out: list[str] = []
    for group in NAV_GROUPS:
        pages = [p for p in PAGES if p.group == group]
        if not pages:
            continue
        out.append('<div class="navgroup">')
        out.append(f'<div class="navtitle">{group}</div>')
        out.append("<ul>")
        for p in pages:
            cls = ' class="current"' if p.slug == current.slug else ""
            out.append(f'<li><a href="{p.slug}.html"{cls}>{html.escape(p.title)}</a></li>')
        out.append("</ul></div>")
    return "\n".join(out)


def render_toc(sections: list[dict]) -> str:
    if not sections:
        return ""
    out = ['<div class="onthispage"><div class="navtitle">On this page</div><ul>']
    for s in sections:
        cls = ' class="lvl3"' if s.get("level") == 3 else ""
        out.append(f'<li{cls}><a href="#{s["id"]}">{html.escape(s["title"])}</a></li>')
    out.append("</ul></div>")
    return "\n".join(out)


def render_page(page: Page, body: str, sections: list[dict], toc: list[dict],
                prev: Page | None, nxt: Page | None) -> str:
    idx = PAGES.index(page)
    crumbs = (
        f'<a href="index.html">Docs</a><span>/</span>'
        f'<span>{html.escape(page.group)}</span><span>/</span>'
        f'<b>{html.escape(page.title)}</b>'
    )
    pn = []
    if prev:
        pn.append(f'<a class="pn prev" href="{prev.slug}.html">'
                  f'<span>Previous</span><b>{html.escape(prev.title)}</b></a>')
    if nxt:
        pn.append(f'<a class="pn next" href="{nxt.slug}.html">'
                  f'<span>Next</span><b>{html.escape(nxt.title)}</b></a>')

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(page.title)} — Attest documentation</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg" />
<meta name="description" content="{html.escape(page.blurb or page.title)}" />
<link rel="stylesheet" href="docs.css" />
<script src="search-index.js"></script>
<script src="docs-search.js" defer></script>
</head>
<body>
<div class="progress" id="progress"></div>
<button class="themebtn" id="theme" type="button" title="Switch light and dark">Light</button>
<button class="navtoggle" id="navtoggle" type="button" aria-label="Toggle contents">☰</button>
<div class="shell">
  <aside id="sidebar">
    <div class="brand">
      <span class="mark" aria-hidden="true">AT</span>
      <div><b>Attest</b><span>Zero Trust, explained</span></div>
    </div>
    <div class="docsearch">
      <input type="search" placeholder="Search all pages…" aria-label="Search all pages" autocomplete="off" />
      <div class="ds-results" hidden></div>
    </div>
    <nav aria-label="Documentation">
      {render_nav(page)}
    </nav>
    {render_toc(toc)}
  </aside>

  <main>
    <div class="crumbs">{crumbs}</div>
    <article>
      <header class="pagehead">
        <h1>{html.escape(page.title)}</h1>
        {f'<p class="blurb">{html.escape(page.blurb)}</p>' if page.blurb else ''}
      </header>
      {body}
    </article>
    <nav class="pager" aria-label="Page navigation">{''.join(pn)}</nav>
    <footer>
      <p><b>Attest</b> — a Zero Trust, passwordless compliance platform. Design complete; one
      verification spike done; no production deployment yet.</p>
      <p>Generated from Markdown by <code>scripts/build_docs.py</code>. These pages are
      self-contained and work offline; search uses a committed index.</p>
    </footer>
  </main>
</div>
<button class="totop" id="totop" type="button">↑ Top</button>
<script>
(function () {{
  var root = document.documentElement;
  var tbtn = document.getElementById('theme');
  var saved = null; try {{ saved = localStorage.getItem('docs-theme'); }} catch (e) {{}}
  if (saved) root.setAttribute('data-theme', saved);
  function sync() {{ tbtn.textContent = root.getAttribute('data-theme') === 'light' ? 'Dark' : 'Light'; }}
  sync();
  tbtn.addEventListener('click', function () {{
    var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try {{ localStorage.setItem('docs-theme', next); }} catch (e) {{}}
    sync();
  }});

  document.querySelectorAll('.codehilite').forEach(function (block) {{
    var pre = block.querySelector('pre'); if (!pre) return;
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'copy'; b.textContent = 'copy';
    b.addEventListener('click', function () {{
      navigator.clipboard.writeText(pre.innerText).then(function () {{
        b.textContent = 'copied'; setTimeout(function () {{ b.textContent = 'copy'; }}, 1200);
      }}, function () {{ b.textContent = 'press Cmd-C'; }});
    }});
    block.appendChild(b);
  }});

  var links = Array.prototype.slice.call(document.querySelectorAll('.onthispage a'));
  var byId = {{}};
  links.forEach(function (a) {{ byId[a.getAttribute('href').slice(1)] = a; }});
  if ('IntersectionObserver' in window && links.length) {{
    var io = new IntersectionObserver(function (entries) {{
      entries.forEach(function (en) {{
        if (!en.isIntersecting) return;
        links.forEach(function (a) {{ a.classList.remove('active'); }});
        if (byId[en.target.id]) byId[en.target.id].classList.add('active');
      }});
    }}, {{ rootMargin: '-8% 0px -82% 0px' }});
    document.querySelectorAll('main section[id]').forEach(function (s) {{ io.observe(s); }});
  }}

  var bar = document.getElementById('progress');
  function onScroll() {{
    var h = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.width = (h > 0 ? Math.min(100, (window.scrollY / h) * 100) : 0) + '%';
  }}
  window.addEventListener('scroll', onScroll, {{ passive: true }});
  onScroll();

  document.getElementById('totop').addEventListener('click', function () {{
    window.scrollTo({{ top: 0, behavior: 'smooth' }});
  }});

  var nb = document.getElementById('navtoggle'), sb = document.getElementById('sidebar');
  nb.addEventListener('click', function () {{ sb.classList.toggle('open'); }});
  sb.addEventListener('click', function (e) {{
    if (e.target.tagName === 'A' && window.innerWidth < 1000) sb.classList.remove('open');
  }});
}})();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------
@dataclass
class Built:
    files: dict[str, str] = field(default_factory=dict)
    index: list[dict] = field(default_factory=list)


def build() -> Built:
    out = Built()
    missing_diagrams: list[str] = []
    unresolved: list[str] = []

    md_pages: list[Page] = []
    for page in PAGES:
        src = ROOT / page.src
        if not src.exists():
            continue
        md_pages.append(page)

    for i, page in enumerate(md_pages):
        src = ROOT / page.src
        raw = src.read_text(encoding="utf-8")

        raw, missing = replace_mermaid(raw, page.src)
        missing_diagrams.extend(missing)

        md = markdown.Markdown(extensions=MD_EXTENSIONS, extension_configs=MD_CONFIG,
                               output_format="html5")
        rendered = md.convert(raw)
        # The page template already renders the title, so the document's own
        # leading H1 would show it twice.
        rendered = re.sub(r"^\s*<h1\b[^>]*>.*?</h1>\s*", "", rendered, count=1, flags=re.S)
        # Bare <table> cannot scroll on its own; a wrapper lets it.
        rendered = re.sub(r"(<table>.*?</table>)",
                          r'<div class="tablewrap">\1</div>', rendered, flags=re.S)
        rendered = rewrite_links(rendered, src, unresolved)

        body, sections = wrap_sections(rendered)
        toc = split_toc(rendered)

        prev = md_pages[i - 1] if i > 0 else None
        nxt = md_pages[i + 1] if i + 1 < len(md_pages) else None
        out.files[f"{page.slug}.html"] = render_page(page, body, sections, toc, prev, nxt)

        for s in sections:
            out.index.append({
                "p": f"{page.slug}.html",
                "a": s["id"],
                "t": s["title"],
                "g": page.group,
                "x": s.get("text", ""),
            })

    # Body text for the search index, taken from the plain section content.
    for rec in out.index:
        key = rec["p"]
        page_html = out.files[key]
        m = re.search(
            rf'<section id="{re.escape(rec["a"])}">(.*?)</section>', page_html, re.S)
        if m:
            text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", m.group(1), flags=re.S | re.I)
            text = re.sub(r"<[^>]+>", " ", text)
            text = html.unescape(re.sub(r"\s+", " ", text)).strip()
            rec["x"] = text[:3000]

    out.files["search-index.js"] = (
        "// Generated by scripts/build_docs.py — do not edit by hand.\n"
        "// Rebuild: python3 scripts/build_docs.py\n"
        "window.__DOCS_SEARCH = "
        + json.dumps(out.index, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
        + ";\n"
    )
    out.files["docs.css"] = site_css()
    if missing_diagrams:
        print(f"WARNING: {len(missing_diagrams)} diagram(s) not pre-rendered: "
              f"{', '.join(sorted(set(missing_diagrams)))}")
    if unresolved:
        print(f"WARNING: {len(unresolved)} link(s) could not be resolved and were left as-is:")
        for u in unresolved:
            print(f"  - {u}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if docs/site is stale")
    ap.add_argument("--force", action="store_true", help="accepted; output is always rewritten")
    args = ap.parse_args()

    built = build()
    stale: list[str] = []
    for name, content in sorted(built.files.items()):
        target = SITE / name
        have = target.read_text(encoding="utf-8") if target.exists() else None
        if have != content:
            stale.append(name)

    if args.check:
        if stale:
            print("STALE: docs/site is out of date with its Markdown sources:")
            for s in stale:
                print(f"  - docs/site/{s}")
            print("\nRun: python3 scripts/build_docs.py")
            return 1
        print(f"OK: docs/site is up to date ({len(built.files)} file(s), "
              f"{len(built.index)} indexed sections).")
        return 0

    SITE.mkdir(parents=True, exist_ok=True)
    for name, content in built.files.items():
        (SITE / name).write_text(content, encoding="utf-8")
    print(f"wrote {len(built.files)} file(s) to docs/site/:")
    for name in sorted(built.files):
        print(f"  {name}")
    print(f"indexed {len(built.index)} sections across {len(PAGES)} page(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
