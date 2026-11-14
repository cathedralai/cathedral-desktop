"""python3 tee/test_wording.py

Fails when customer-facing text uses a phrase from the "Not allowed" list in tee/PROMISE.md. It matches a fixed
list of phrases (BANNED below); it does not catch every overclaim.

Scope, exactly: Markdown (README.md and tee/**/*.md), the HTML of tee/web/*.html (tags dropped, inline script
comments included) and the string literals of tee/web/*.js (comments in the .js files are not read).
Not scanned: desktop/web/index.html, the Python client's messages in tee/client, the box daemon's error
strings in tee/boxd that the page prints, other code, and test files (test-*.mjs, test_*.py).

Each file is normalised before matching, so a wrapped line, a doubled or non-breaking space, a Unicode hyphen,
Markdown marks, HTML tags and entities, JS string concatenation and template expressions do not hide a phrase.

A place where a banned phrase is legitimately used goes in ALLOW below, with the rule it silences, the exact
text it covers and a reason. An entry silences only that rule, only inside that text. An entry that no longer
matches anything fails the run, so the list cannot rot.
"""
import html as htmllib
import os
import re
import tempfile
import unicodedata
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, regex, why it is banned, optional regex the sentence of the hit must also match).
# Matched case-insensitively against the normalised text of a file.
CAPACITY = r"\b(?:pool|box|boxes|desktop|desktops|capacity|sealed)\b"
SEEING = r"(?:see|view|watch|look at|peek at)"
BANNED = [
    ("proof", r"\bproofs?\b(?!(?:-| )of(?:-| )work)", "claims a proof; say what the check shows instead", None),
    ("prove", r"\bprov(?:e|es|ed|en|ing|able|ably)\b", "claims a proof; say what the check shows instead", None),
    ("Cathedral-signed", r"cathedral[- ]signed", "the AMD chip vouches for reports (S9)", None),
    ("no one can see", r"\b(?:no ?one|nobody|no-one) can " + SEEING + r"\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("not even Cathedral", r"\bnot even cathedral\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("Cathedral cannot see", r"\bcathedral (?:cannot|can't|can not) " + SEEING + r"\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("anyone can rebuild", r"\banyone can rebuild\b", "not before the second-host build passes", None),
    ("host cannot change the software", r"\bhost (?:cannot|can't|can not) change the software\b", "not until P2 is closed", None),
    ("only you can see", r"end-to-end encrypted so only you can see", "the hosted page and the ticket key holder can see", None),
    ("unavailable", r"\bunavailable\b", "a busy sealed pool is \"sold out\"; banned in a sentence about capacity", CAPACITY),
]

# (file relative to the repo root, rule name, exact normalised text it covers, reason). Short on purpose.
# The "Not allowed" list in tee/PROMISE.md has to quote the banned claims to forbid them.
_Q = "PROMISE.md quotes the banned phrase to forbid it"
ALLOW = [
    ("tee/PROMISE.md", "no one can see", '"No one can see inside"', _Q),
    ("tee/PROMISE.md", "not even Cathedral", '"not even Cathedral"', _Q),
    ("tee/PROMISE.md", "Cathedral cannot see", '"Cathedral cannot see"', _Q),
    ("tee/PROMISE.md", "proof", 'Any "proof", "proves", "prove", "provable" or "provably"', _Q),
    ("tee/PROMISE.md", "prove", 'Any "proof", "proves", "prove", "provable" or "provably"', _Q),
    ("tee/PROMISE.md", "Cathedral-signed", '"Cathedral-signed"', _Q),
    ("tee/PROMISE.md", "anyone can rebuild", '"Anyone can rebuild"', _Q),
    ("tee/PROMISE.md", "host cannot change the software", '"The host cannot change the software"', _Q),
    ("tee/PROMISE.md", "only you can see", '"End-to-end encrypted so only you can see."', _Q),
    ("tee/PROMISE.md", "unavailable", '"Unavailable" for a busy sealed pool', _Q),
]

_HYPHENS = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u00ad\ufe58\ufe63\uff0d"), "-")
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def _js_unescape(lit):
    def one(m):
        e = m.group(1)
        if e[0] in "ux":
            return chr(int(e[1:].strip("{}"), 16))
        return {"n": " ", "t": " ", "r": " "}.get(e, e)
    return re.sub(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", one, lit, flags=re.S)


def js_strings(src):
    """The text of the string and template literals of JavaScript source. Literals joined by + become one
    string; every other pair is separated by a newline. Template expressions drop out. Comments are skipped."""
    parts, i, n, prev_end = [], 0, len(src), None
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
            body = src[i + 1:j]
            if c == "`":
                body = re.sub(r"\$\{[^}]*\}", "", body)
            body = _js_unescape(body)
            if prev_end is not None and re.fullmatch(r"\s*\+\s*", src[prev_end:i]):
                parts[-1] += body
            else:
                parts.append(body)
            prev_end = i = j + 1
        else:
            i += 1
    return "\n".join(parts)


def _markup_text(text):
    text = htmllib.unescape(text)
    text = re.sub(r"</?[A-Za-z][^>]*>|<!--.*?-->", "", text, flags=re.S)
    return htmllib.unescape(text)


def _markdown_text(text):
    text = re.sub(r"^[ \t]*(?:>[ \t]*)+", "", text, flags=re.M)
    text = re.sub(r"^[ \t]*(?:[-*+]|\d+\.)[ \t]+", "", text, flags=re.M)
    return re.sub(r"[*_`~\[\]]", "", text)


def normalise(rel, text):
    """One line of plain text per file, so a phrase matches however it was written."""
    if rel.endswith(".js"):
        s = js_strings(text)
    elif rel.endswith(".html"):
        scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", text, flags=re.S))
        s = _markup_text(text) + "\n" + js_strings(scripts)
    else:
        s = _markdown_text(_markup_text(text))
    s = unicodedata.normalize("NFKC", s).translate(_HYPHENS).translate(_INVISIBLE)
    return " ".join(s.split())


def _sentence(text, start, end):
    a = max((m.end() for m in re.finditer(r"[.!?]\s", text[:start])), default=0)
    m = re.search(r"[.!?](?:\s|$)", text[end:])
    return text[a:end + (m.end() if m else len(text) - end)]


def find_violations(rel, text, allow, used):
    """[(file, offset in the normalised text, rule name, context)] for the hits that no allow entry covers."""
    norm = normalise(rel, text)
    found = []
    for name, rx, _why, only_in in BANNED:
        for m in re.finditer(rx, norm, re.I):
            if only_in and not re.search(only_in, _sentence(norm, m.start(), m.end()), re.I):
                continue
            covered = [k for k, (f, rule, sub, _r) in enumerate(allow) if f == rel and rule == name and any(
                o.start() <= m.start() and m.end() <= o.end() for o in re.finditer(re.escape(normalise(rel, sub)), norm))]
            if covered:
                used.update(covered)
            else:
                found.append((rel, m.start(), name, norm[max(0, m.start() - 40):m.end() + 40]))
    return found


def customer_files(root):
    files = ["README.md"] if os.path.exists(os.path.join(root, "README.md")) else []
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
        self.assertEqual(found, [], "banned claims:\n" + "\n".join(f"{f} [{name}] ...{ctx}..." for f, _n, name, ctx in found))

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

    def rules(self, files, allow=()):
        found, _ = scan(self.tree(files), list(allow))
        return sorted({name for _f, _n, name, _c in found})

    def test_planted_banned_sentence_fails(self):
        root = self.tree({"README.md": "# x\nNo one can see inside the box.\n", "tee/web/a.js": "const m = 'This proves it';\n"})
        found, _ = scan(root, [])
        self.assertEqual(sorted((f, name) for f, _n, name, _c in found), [("README.md", "no one can see"), ("tee/web/a.js", "prove")])

    def test_allow_listed_use_passes(self):
        root = self.tree({"README.md": "Never say: the pool is unavailable.\n"})
        allow = [("README.md", "unavailable", "Never say: the pool is unavailable", "quoted as a banned phrase")]
        self.assertEqual(scan(root, allow), ([], []))
        self.assertEqual([h[2] for h in scan(root, [])[0]], ["unavailable"])

    def test_allow_entry_that_matches_nothing_fails(self):
        root = self.tree({"README.md": "Clean text.\n"})
        allow = [("README.md", "unavailable", "old wording", "gone")]
        _, stale = scan(root, allow)
        self.assertEqual(stale, allow)

    # One test per way of writing the phrase so a line-by-line match would miss it.
    def test_phrase_split_by_a_line_wrap(self):
        self.assertEqual(self.rules({"README.md": "Today no one\ncan see the box.\n"}), ["no one can see"])

    def test_phrase_split_by_a_wrapped_blockquote_and_list(self):
        self.assertEqual(self.rules({"README.md": "> no one\n> can see it\n\n- anyone\n  can rebuild it\n"}), ["anyone can rebuild", "no one can see"])

    def test_phrase_with_two_spaces(self):
        self.assertEqual(self.rules({"README.md": "no one  can   see it\n"}), ["no one can see"])

    def test_phrase_with_a_non_breaking_space(self):
        self.assertEqual(self.rules({"README.md": "no one\u00a0can\u00a0see it\n"}), ["no one can see"])

    def test_phrase_with_a_unicode_hyphen(self):
        self.assertEqual(self.rules({"README.md": "It is Cathedral\u2011signed.\n"}), ["Cathedral-signed"])

    def test_phrase_with_a_zero_width_character(self):
        self.assertEqual(self.rules({"README.md": "It pro\u200bves it.\n"}), ["prove"])

    def test_phrase_with_markdown_marks(self):
        self.assertEqual(self.rules({"README.md": "**no one** can `see` _it_\n"}), ["no one can see"])

    def test_phrase_with_html_tags(self):
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no <b>one</b> can <i>see</i> it</p>\n"}), ["no one can see"])

    def test_phrase_with_html_entities(self):
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no&nbsp;one can &lt;b&gt;see&lt;/b&gt; it</p>\n"}), ["no one can see"])

    def test_phrase_with_js_string_concatenation(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = 'no one ' +\n  \"can see\" + ' it';\n"}), ["no one can see"])

    def test_phrase_with_a_js_template_expression(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `no one ${x}can see it`;\n"}), ["no one can see"])

    def test_phrase_with_a_js_unicode_escape(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = 'Cathedral\\u2011signed';\n"}), ["Cathedral-signed"])

    def test_provably_is_banned(self):
        self.assertEqual(self.rules({"README.md": "It is provably private.\n"}), ["prove"])

    # An allow-list entry silences the rule it names, on the text it names, and nothing else.
    def test_allow_entry_does_not_silence_another_rule_on_its_line(self):
        with open(os.path.join(ROOT, "tee", "PROMISE.md"), encoding="utf-8") as fh:
            text = fh.read()
        quoted = '"No one can see inside"'
        self.assertIn(quoted, text)
        root = self.tree({"tee/PROMISE.md": text.replace(quoted, quoted + " This proves the box is private.", 1)})
        found, _ = scan(root, ALLOW)
        self.assertEqual([h[2] for h in found], ["prove"])

    def test_allow_entry_does_not_silence_a_second_use_of_the_same_rule(self):
        allow = [("README.md", "no one can see", '"no one can see inside"', "quoted")]
        root = self.tree({"README.md": 'Never say "no one can see inside". Also no one can see it.\n'})
        found, _ = scan(root, allow)
        self.assertEqual([h[2] for h in found], ["no one can see"])

    # Honest text must pass.
    def test_honest_text_passes(self):
        for text in ("The AMD KDS was unavailable.", "It uses proof-of-work.", "Nobody can read the frames without the box key.",
                     "The pool is sold out.", "A proof of work is not used here."):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), [])

    def test_unavailable_is_banned_about_capacity(self):
        for text in ("The pool is unavailable.", "The sealed desktop is unavailable right now.", "Capacity is unavailable."):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), ["unavailable"])


def promise_sentences():
    with open(os.path.join(ROOT, "tee", "PROMISE.md"), encoding="utf-8") as fh:
        found = re.findall(r"^- (S\d) (.+)$", fh.read(), re.M)
    return [t for _k, t in found]


def readme_tee_sentences():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        text = fh.read()
    section = text.split("## The TEE box (tee/)", 1)[1].split("\n## ", 1)[0]
    bullets = re.split(r"\n- ", "\n" + section.split("\n- ", 1)[1] if "\n- " in section else "")
    return [" ".join(b.split()) for b in bullets if b.strip()]


class ReadmeMatchesPromise(unittest.TestCase):
    def test_readme_has_the_nine_sentences_word_for_word(self):
        want = [" ".join(t.split()) for t in promise_sentences()]
        self.assertEqual(len(want), 9)
        self.assertEqual(readme_tee_sentences(), want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
