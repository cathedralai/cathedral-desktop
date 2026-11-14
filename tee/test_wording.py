"""python3 tee/test_wording.py

Fails when customer-facing text claims more than the TEE box does today (tee/PROMISE.md, sentences S1 to S9).
Scope: Markdown (README.md, tee/**/*.md), HTML (tee/web/*.html) and the string literals of tee/web/*.js.
Code comments are NOT scanned, and neither are other code files or test files (test-*.mjs, test_*.py): they
are not customer-facing. The same scope is stated in tee/PROMISE.md.

A place where a banned word is legitimately used goes in ALLOW below, with a reason. An entry that no
longer matches anything fails the run, so the list cannot rot.
"""
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, regex, why it is banned). Matched case-insensitively against each line.
BANNED = [
    ("proof", r"\bproofs?\b", "claims a proof; say what the check shows instead"),
    ("prove", r"\bprov(?:e|es|ed|en|ing|able)\b", "claims a proof; say what the check shows instead"),
    ("Cathedral-signed", r"cathedral[- ]signed", "the AMD chip vouches for reports (S9)"),
    ("no one can see", r"\b(?:no ?one|nobody|no-one) can (?:see|read|look)\b", "not true while Cathedral holds the ticket key (S6)"),
    ("not even Cathedral", r"\bnot even cathedral\b", "not true while Cathedral holds the ticket key (S6)"),
    ("Cathedral cannot see", r"\bcathedral (?:cannot|can't|can not) (?:see|read|look)\b", "not true while Cathedral holds the ticket key (S6)"),
    ("anyone can rebuild", r"\banyone can rebuild\b", "not before the second-host build passes"),
    ("host cannot change the software", r"\bhost (?:cannot|can't|can not) change the software\b", "not until Cloud Hypervisor stage0 is closed"),
    ("only you can see", r"end-to-end encrypted so only you can see", "the hosted page and the ticket key holder can see"),
    ("unavailable", r"\bunavailable\b", "a busy sealed pool is \"sold out\""),
]

# (file relative to the repo root, exact substring of the line, reason). Short on purpose.
# The "Not allowed" list in tee/PROMISE.md has to quote the banned claims to forbid them.
ALLOW = [
    ("tee/PROMISE.md", '"No one can see inside"', "PROMISE.md quotes the banned sentence to forbid it"),
    ("tee/PROMISE.md", 'Any "proof"', "PROMISE.md quotes the banned words to forbid them"),
    ("tee/PROMISE.md", '"Cathedral-signed"', "PROMISE.md quotes the banned word to forbid it"),
    ("tee/PROMISE.md", '"Anyone can rebuild"', "PROMISE.md quotes the banned sentence to forbid it"),
    ("tee/PROMISE.md", '"The host cannot change the software"', "PROMISE.md quotes the banned sentence to forbid it"),
    ("tee/PROMISE.md", '"End-to-end encrypted so only you can see."', "PROMISE.md quotes the banned sentence to forbid it"),
    ("tee/PROMISE.md", '"Unavailable" for a busy', "PROMISE.md quotes the banned word to forbid it"),
]


def js_strings(src):
    """The string and template literals of JavaScript source, one per line of output, comments dropped."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i)
            i = n if i < 0 else i + 2
        elif c in "'\"`":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i + 1:j])
            i = j + 1
        else:
            i += 1
    return "\n".join(out)


def customer_text(rel, text):
    return js_strings(text) if rel.endswith(".js") else text


def find_violations(rel, text, allow, used):
    """[(rel, line number, banned name, line)] for the lines of this file that break a rule and are not allowed."""
    found = []
    for no, line in enumerate(customer_text(rel, text).splitlines(), 1):
        for name, rx, _why in BANNED:
            if not re.search(rx, line, re.I):
                continue
            hit = [k for k, (f, sub, _r) in enumerate(allow) if f == rel and sub in line]
            if hit:
                used.update(hit)
            else:
                found.append((rel, no, name, line.strip()))
    return found


def customer_files(root):
    files = ["README.md"]
    for base, dirs, names in os.walk(os.path.join(root, "tee")):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
        for nm in names:
            rel = os.path.relpath(os.path.join(base, nm), root)
            if nm.endswith(".md") or (os.path.dirname(rel) == os.path.join("tee", "web") and nm.endswith((".html", ".js"))):
                files.append(rel)
    return sorted(files)


def stale_allow(allow, used):
    return [allow[k] for k in range(len(allow)) if k not in used]


def scan(root, allow):
    used, found = set(), []
    for rel in customer_files(root):
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            found += find_violations(rel, fh.read(), allow, used)
    return found, stale_allow(allow, used)


class RepositoryText(unittest.TestCase):
    def test_no_banned_claim_in_customer_text(self):
        found, _ = scan(ROOT, ALLOW)
        self.assertEqual(found, [], "banned claims:\n" + "\n".join(f"{f}:{n} [{name}] {line}" for f, n, name, line in found))

    def test_every_allow_entry_is_still_used(self):
        _, stale = scan(ROOT, ALLOW)
        self.assertEqual(stale, [], "allow-list entries that match nothing: %r" % (stale,))


class GuardSelfTest(unittest.TestCase):
    def tree(self, files):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        for rel, body in files.items():
            p = os.path.join(d.name, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)
        return d.name

    def test_planted_banned_sentence_fails(self):
        root = self.tree({"README.md": "# x\nNo one can see inside the box.\n", "tee/web/a.js": "const m = 'This proves it';\n"})
        found, _ = scan(root, [])
        self.assertEqual(sorted((f, name) for f, _n, name, _l in found), [("README.md", "no one can see"), ("tee/web/a.js", "prove")])

    def test_allow_listed_use_passes(self):
        root = self.tree({"README.md": "Never say: the pool is unavailable.\n"})
        allow = [("README.md", "Never say: the pool is unavailable", "quoted as a banned phrase")]
        self.assertEqual(scan(root, allow), ([], []))
        self.assertEqual(scan(root, [])[0][0][:3], ("README.md", 1, "unavailable"))

    def test_allow_entry_that_matches_nothing_fails(self):
        root = self.tree({"README.md": "Clean text.\n"})
        allow = [("README.md", "old wording", "gone")]
        _, stale = scan(root, allow)
        self.assertEqual(stale, allow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
