#!/usr/bin/env python3
"""Convert Surge .sgmodule rule sets into AdGuard filter lists.

Reads sources.json (a list of modules), downloads each .sgmodule, converts the
[Rule] section into AdGuard "basic rule" syntax and writes:

  * <out>      - full list (DOMAIN rules + URL rules; URL rules need HTTPS filtering)
  * <dns_out>  - domain-only list that also works in DNS filtering / AdGuard Home

Only the Python standard library is used.

Conversion table
----------------
  DOMAIN,host,REJECT              -> ||host^
  DOMAIN-SUFFIX,host,REJECT       -> ||host^
  DOMAIN-KEYWORD,kw,REJECT        -> ||*kw*^
  URL-REGEX,^https:\/\/h\/p...,REJECT
        -> ||h/p...   when the regex only uses a small, well understood subset
        -> /regex/    otherwise (kept verbatim as an AdGuard regex rule)
  REJECT-TINYGIF / REJECT-IMG     -> add $redirect=1x1-transparent.gif
  REJECT-DICT / REJECT-ARRAY      -> add $redirect=noopjson / nooptext... (see MODIFIERS)
  DIRECT / other policies         -> skipped (nothing to block)

Regex -> basic rule subset:
  ^https?://  or ^https://  or ^http://       start anchor + scheme
  (?::443)? (?::\d+)?                          optional port, dropped
  \/ \. \- \? \_ \=                            escaped literals
  \d+ \d* \w+ [^/]+ [^/]* .+ .* [0-9]+ ...     -> *
  (?:\?|$) (?:$|\?) (?:[?#]|$) (?:\?|\/|$)     -> ^   (end or separator)
  $                                            -> |   (end of address)
  (?:lass|ladg|lads)  literal alternation      -> one rule per alternative
Anything else falls back to a regex rule.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "sgmodule-to-adguard/1.0 (+https://github.com)"

# Surge policy -> AdGuard modifier appended after "$"
MODIFIERS = {
    "REJECT": "",
    "REJECT-DROP": "",
    "REJECT-NO-DROP": "",
    "REJECT-TINYGIF": "redirect=1x1-transparent.gif",
    "REJECT-IMG": "redirect=1x1-transparent.gif",
    "REJECT-DICT": "redirect=noopjson",
    "REJECT-ARRAY": "redirect=noopjson",
}

# Regex fragments that map to the AdGuard "*" wildcard
WILDCARD_TOKENS = [
    r"\d+", r"\d*", r"\w+", r"\w*", r"[^/]+", r"[^/]*", r"[^\/]+", r"[^\/]*",
    r".+", r".*", r"[0-9]+", r"[0-9]*", r"[a-z0-9]+", r"[a-zA-Z0-9]+",
    r"[A-Za-z0-9]+", r"[a-z]+", r"[A-Za-z]+", r"[\w-]+", r"[\w\-]+",
    r"[\w.-]+", r"[\w\.\-]+", r"[a-z0-9_-]+", r"[a-zA-Z0-9_-]+",
    r"[a-z0-9-]+", r"[a-zA-Z0-9-]+", r"\d{1,}", r"[^?]+", r"[^?]*",
    r"[^&]+", r"[^&]*",
]
WILDCARD_TOKENS.sort(key=len, reverse=True)

# Regex fragments meaning "end of path segment or end of URL" -> "^"
SEPARATOR_END_TOKENS = [
    r"(?:\?|$)", r"(?:$|\?)", r"(?:[?#]|$)", r"(?:[#?]|$)", r"(?:\?|#|$)",
    r"(?:\?|\/|$)", r"(?:\/|\?|$)", r"(?:\/|$)", r"(?:$|\/)",
    r"(\?|$)", r"($|\?)", r"(\/|$)", r"(\?.*)?$", r"(?:\?.*)?$",
    r"(\/.*)?$", r"(?:\/.*)?$",
]
SEPARATOR_END_TOKENS.sort(key=len, reverse=True)

# Port groups that can simply be dropped (AdGuard ignores the default port)
PORT_TOKENS = [r"(?::443)?", r"(?::80)?", r"(?::\d+)?", r"(?::\d*)?", r"(:443)?", r"(:\d+)?"]

SCHEME_RE = re.compile(r"^\^(?:https\?:|https?:|http:|https:)\\?/\\?/")
HOST_RE = re.compile(r"^((?:[A-Za-z0-9-]+\\\.)+[A-Za-z0-9-]+)")

# Characters allowed verbatim in an AdGuard basic rule body
PLAIN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~.,:;=&%+@")
ESCAPED_LITERALS = {"/": "/", ".": ".", "-": "-", "?": "?", "_": "_", "=": "=", "&": "&", ",": ",", ":": ":", "%": "%", "+": "+", "~": "~", "@": "@"}


class RegexTooComplex(Exception):
    pass


ALT_GROUP_RE = re.compile(r"\(\?:((?:[A-Za-z0-9_\-]|\\[./\-_])+(?:\|(?:[A-Za-z0-9_\-]|\\[./\-_])+)+)\)(?![*+?{])")
MAX_EXPANSION = 32


def expand_alternations(pattern: str) -> list[str]:
    """Expand literal-only groups such as (?:lass|ladg|lads) into separate patterns."""
    patterns = [pattern]
    while True:
        expanded: list[str] = []
        changed = False
        for pat in patterns:
            m = ALT_GROUP_RE.search(pat)
            if not m:
                expanded.append(pat)
                continue
            changed = True
            for alt in m.group(1).split("|"):
                expanded.append(pat[:m.start()] + alt + pat[m.end():])
        if len(expanded) > MAX_EXPANSION:
            return [pattern]
        patterns = expanded
        if not changed:
            return patterns


def regex_to_basic(pattern: str) -> str:
    """Translate a Surge URL-REGEX into an AdGuard basic rule body, or raise."""
    m = SCHEME_RE.match(pattern)
    if not m:
        raise RegexTooComplex("no anchored scheme")
    rest = pattern[m.end():]

    hm = HOST_RE.match(rest)
    if not hm:
        raise RegexTooComplex("host not literal")
    host = hm.group(1).replace("\\.", ".")
    rest = rest[hm.end():]

    for tok in PORT_TOKENS:
        if rest.startswith(tok):
            rest = rest[len(tok):]
            break

    out = []
    i = 0
    n = len(rest)
    while i < n:
        matched = False
        for tok in SEPARATOR_END_TOKENS:
            if rest.startswith(tok, i) and i + len(tok) == n:
                out.append("^")
                i = n
                matched = True
                break
        if matched:
            break
        for tok in WILDCARD_TOKENS:
            if rest.startswith(tok, i):
                if out and out[-1] == "*":
                    pass
                else:
                    out.append("*")
                i += len(tok)
                matched = True
                break
        if matched:
            continue
        ch = rest[i]
        if ch == "\\":
            if i + 1 >= n:
                raise RegexTooComplex("dangling backslash")
            nxt = rest[i + 1]
            if nxt in ESCAPED_LITERALS:
                out.append(ESCAPED_LITERALS[nxt])
                i += 2
                continue
            raise RegexTooComplex(f"unsupported escape \\{nxt}")
        if ch == "$" and i == n - 1:
            out.append("|")
            i += 1
            continue
        if ch == "/":
            out.append("/")
            i += 1
            continue
        if ch in PLAIN_CHARS:
            out.append(ch)
            i += 1
            continue
        raise RegexTooComplex(f"unsupported char {ch!r}")

    body = "".join(out)
    # A host-only regex such as ^https://host(?::443)?/ -> ||host^
    if body in ("", "/"):
        return f"||{host}^"
    if not body.startswith("/"):
        raise RegexTooComplex("path does not start with /")
    return f"||{host}{body}"


def domain_from_regex(pattern: str) -> str | None:
    m = SCHEME_RE.match(pattern)
    if not m:
        return None
    hm = HOST_RE.match(pattern[m.end():])
    if not hm:
        return None
    return hm.group(1).replace("\\.", ".")


def add_modifier(rule: str, modifier: str) -> str:
    if not modifier:
        return rule
    return f"{rule}${modifier}"


def split_surge_rule(line: str) -> list[str]:
    """Split 'TYPE,value,POLICY[,opts]' keeping regex commas intact."""
    parts = line.split(",")
    if len(parts) < 3:
        return parts
    rtype = parts[0].strip()
    policy_idx = None
    for idx in range(len(parts) - 1, 0, -1):
        p = parts[idx].strip().upper()
        if p in MODIFIERS or p in ("DIRECT", "PROXY") or p.startswith("REJECT"):
            policy_idx = idx
            break
    if policy_idx is None:
        return [rtype, ",".join(parts[1:-1]).strip(), parts[-1].strip()]
    return [rtype, ",".join(parts[1:policy_idx]).strip(), parts[policy_idx].strip()] + [p.strip() for p in parts[policy_idx + 1:]]


def convert(text: str, source_url: str, name: str, homepage: str) -> tuple[list[str], list[str], dict]:
    """Return (full_rules, dns_rules, meta)."""
    meta = {"name": None, "desc": None, "version": None, "mitm": None}
    full: list[str] = []
    dns: list[str] = []
    stats = {"domain": 0, "basic": 0, "regex": 0, "skipped": 0}
    section = None
    seen_dns: set[str] = set()

    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        stripped = line.strip()

        if stripped.startswith("#!"):
            key, _, val = stripped[2:].partition("=")
            key = key.strip().lower()
            if key in ("name", "desc"):
                meta[key] = val.strip()
                if key == "desc":
                    vm = re.search(r"v?(\d{8}(?:\.\d+)?)", val)
                    if vm:
                        meta["version"] = vm.group(1)
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue

        if section == "mitm":
            if stripped.lower().startswith("hostname"):
                _, _, hosts = stripped.partition("=")
                hosts = hosts.replace("%APPEND%", "").replace("%INSERT%", "")
                meta["mitm"] = [h.strip() for h in hosts.split(",") if h.strip()]
            continue

        if section != "rule":
            continue

        if not stripped:
            if full and full[-1] != "":
                full.append("")
            continue

        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
            comment = stripped.lstrip("#/; ").rstrip()
            full.append(f"! {comment}" if comment else "!")
            continue

        parts = split_surge_rule(stripped)
        if len(parts) < 3:
            full.append(f"! [skipped] {stripped}")
            stats["skipped"] += 1
            continue
        rtype = parts[0].upper()
        value = parts[1]
        policy = parts[2].upper()

        if policy not in MODIFIERS:
            full.append(f"! [skipped, policy {policy}] {stripped}")
            stats["skipped"] += 1
            continue
        modifier = MODIFIERS[policy]

        if rtype in ("DOMAIN", "DOMAIN-SUFFIX"):
            rule = add_modifier(f"||{value}^", modifier)
            full.append(rule)
            if value not in seen_dns:
                dns.append(f"||{value}^")
                seen_dns.add(value)
            stats["domain"] += 1
        elif rtype == "DOMAIN-KEYWORD":
            full.append(add_modifier(f"||*{value}*^", modifier))
            dns.append(f"||*{value}*^")
            stats["domain"] += 1
        elif rtype == "URL-REGEX":
            try:
                rules = [regex_to_basic(p) for p in expand_alternations(value)]
                stats["basic"] += len(rules)
            except RegexTooComplex:
                rules = [f"/{value}/"]
                stats["regex"] += 1
            full.extend(add_modifier(r, modifier) for r in rules)
        else:
            full.append(f"! [skipped, {rtype} not supported] {stripped}")
            stats["skipped"] += 1

    while full and full[-1] == "":
        full.pop()
    meta["stats"] = stats
    return full, dns, meta


def header(title: str, desc: str, version: str | None, homepage: str, source: str,
           now: str, extra: list[str]) -> list[str]:
    lines = [
        f"! Title: {title}",
        f"! Description: {desc}",
        f"! Version: {version or 'unknown'}",
        f"! Last modified: {now}",
        "! Expires: 1 day (update frequency)",
        f"! Homepage: {homepage}",
        f"! Source: {source}",
        "! Converted automatically from the Surge module above; do not edit by hand.",
    ]
    lines.extend(extra)
    lines.append("!")
    return lines


def strip_timestamp(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.startswith("! Last modified:"))


def write_if_changed(path: Path, content: str) -> bool:
    if path.exists():
        old = path.read_text(encoding="utf-8")
        if strip_timestamp(old) == strip_timestamp(content):
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="sources.json", help="path to sources.json")
    ap.add_argument("--from-file", help="convert a local .sgmodule instead of downloading (uses the first source entry)")
    ap.add_argument("--homepage", default=None, help="override homepage URL from config")
    args = ap.parse_args(argv)

    root = Path(args.config).resolve().parent
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    homepage = args.homepage or config.get("homepage", "")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    changed_any = False
    for src in config["sources"]:
        if args.from_file:
            text = Path(args.from_file).read_text(encoding="utf-8")
        else:
            print(f"[fetch] {src['url']}")
            text = fetch(src["url"])

        full, dns, meta = convert(text, src["url"], src["name"], homepage)
        title = src.get("title") or meta["name"] or src["name"]
        desc = meta["desc"] or ""
        stats = meta["stats"]

        extra = [
            f"! Rules: {stats['domain']} domain, {stats['basic']} URL (basic), {stats['regex']} URL (regex), {stats['skipped']} skipped",
        ]
        if meta["mitm"]:
            extra.append("! URL rules only work with AdGuard HTTPS filtering enabled for these hosts:")
            extra.append("!   " + ", ".join(meta["mitm"]))

        full_text = "\n".join(header(title, desc, meta["version"], homepage, src["url"], now, extra) + full) + "\n"
        out_path = root / src["out"]
        if write_if_changed(out_path, full_text):
            print(f"[write] {out_path} (version {meta['version']})")
            changed_any = True
        else:
            print(f"[same ] {out_path}")

        if src.get("dns_out"):
            dns_extra = ["! Domain-only subset: works without HTTPS filtering (DNS filtering, AdGuard Home, Private DNS)."]
            dns_text = "\n".join(header(f"{title} (DNS only)", desc, meta["version"], homepage, src["url"], now, dns_extra) + dns) + "\n"
            dns_path = root / src["dns_out"]
            if write_if_changed(dns_path, dns_text):
                print(f"[write] {dns_path}")
                changed_any = True
            else:
                print(f"[same ] {dns_path}")

        if args.from_file:
            break

    print("changed" if changed_any else "unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
