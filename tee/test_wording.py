"""python3 tee/test_wording.py

Fails when customer-facing text uses a phrase from the "Not allowed" list in tee/PROMISE.md. It matches a fixed
list of phrases (BANNED below); it does not catch every overclaim.

Scope, exactly: Markdown (README.md and tee/**/*.md), the HTML of tee/web/*.html (the text, the values of the
title, alt, aria-label and placeholder attributes, and the inline script's comments; HTML comments are not read)
and the string literals of tee/web/*.js (comments in the .js files are not read).
Not scanned: desktop/web/index.html, the Python client's messages in tee/client, the box daemon's error
strings in tee/boxd that the page prints, other code, and test files (test-*.mjs, test_*.py).

Each file is normalised before matching, so a wrapped line, a doubled or non-breaking space, a Unicode hyphen,
a soft hyphen, Markdown marks, HTML tags and entities, JS string concatenation and template expressions do not
hide a phrase. A list item, a table row or cell, a heading, a paragraph, a block-level HTML tag and a separate JS
literal each end a sentence; a phrase never matches across that end.

A place where a banned phrase is legitimately used goes in ALLOW below: the file, the rule it silences, the full
text of the line (block) it is in, and a reason. An entry silences only that rule, on that one line, once. A
second use of the phrase anywhere else in the file fails, and an entry that matches nothing fails, so the list
cannot rot.
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
CAPACITY = r"\b(?:pool|pools|box|boxes|desktop|desktops|capacity|sealed|room|rooms|hotel|hotels)\b"
SEEING = r"(?:see|read|view|watch|look|peek)"
BANNED = [
    ("proof", r"\bproofs?\b(?!-of-work\b)", "claims a proof; say what the check shows instead", None),
    ("prove", r"\bprov(?:e|es|ed|en|ing|able|ably)\b", "claims a proof; say what the check shows instead", None),
    ("Cathedral-signed", r"cathedral[- ]signed", "the AMD chip vouches for reports (S9)", None),
    # "read the frames" is the one honest use of the verb: the frames are encrypted to the box key (S4).
    ("no one can see", r"\b(?:no ?one|nobody|no-one) can (?:see|read(?! the (?:encrypted )?frames\b)|view|watch|look|peek)\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("not even Cathedral", r"\bnot even cathedral\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("Cathedral cannot see", r"\bcathedral (?:cannot|can't|can not) " + SEEING + r"\b", "not true while Cathedral holds the ticket key (S6)", None),
    ("anyone can rebuild", r"\banyone can rebuild\b", "not before the second-host build passes", None),
    ("host cannot change the software", r"\bhost (?:cannot|can't|can not) change the software\b", "not until P2 is closed", None),
    ("only you can see", r"end-to-end encrypted so only you can see", "the hosted page and the ticket key holder can see", None),
    ("unavailable", r"\bunavailable\b", "a busy sealed pool is \"sold out\"; banned in a sentence about capacity", CAPACITY),
]

# (file relative to the repo root, rule name, the full text of the one line it covers, reason).
# Short on purpose. The "Not allowed" list in tee/PROMISE.md has to quote the banned claims to forbid them.
_Q = "PROMISE.md quotes the banned phrase to forbid it"
_L1 = ('"No one can see inside", "not even Cathedral", "Cathedral cannot see": not until all of these hold. '
       'Customer mode is live in a listed build. A local client checks it. A firmware floor is set '
       '(an owner decision, not yet made). Others can rebuild that build.')
_L2 = 'Any "proof", "proves", "prove", "provable" or "provably" about the product.'
ALLOW = [
    ("tee/PROMISE.md", "no one can see", _L1, _Q),
    ("tee/PROMISE.md", "not even Cathedral", _L1, _Q),
    ("tee/PROMISE.md", "Cathedral cannot see", _L1, _Q),
    ("tee/PROMISE.md", "proof", _L2, _Q),
    ("tee/PROMISE.md", "prove", _L2, _Q),
    ("tee/PROMISE.md", "Cathedral-signed", '"Cathedral-signed". The AMD chip vouches for reports (S9).', _Q),
    ("tee/PROMISE.md", "anyone can rebuild", '"Anyone can rebuild": not before the second-host build passes.', _Q),
    ("tee/PROMISE.md", "host cannot change the software", '"The host cannot change the software": not until P2 is closed.', _Q),
    ("tee/PROMISE.md", "only you can see", '"End-to-end encrypted so only you can see."', _Q),
    ("tee/PROMISE.md", "unavailable", '"Unavailable" for a busy sealed pool. Say "sold out".', _Q),
]

SENT = "\x01"  # marks the end of a sentence-like block: list item, table row or cell, paragraph, block tag, JS literal
_BLOCK_TAGS = {"p", "div", "li", "ul", "ol", "tr", "td", "th", "table", "thead", "tbody", "h1", "h2", "h3", "h4", "h5",
               "h6", "hr", "section", "article", "main", "header", "footer", "nav", "aside", "pre", "blockquote",
               "dl", "dt", "dd", "figure", "figcaption", "form", "button", "option", "select", "title"}

_HYPHENS = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"), "-")
_APOSTROPHES = dict.fromkeys(map(ord, "\u2018\u2019\u02bc\uff07"), "'")
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"), None)


def _js_unescape(lit):
    def one(m):
        e = m.group(1)
        if e[0] in "ux":
            return chr(int(e[1:].strip("{}"), 16))
        return {"n": " ", "t": " ", "r": " ", "\n": "", "\r": ""}.get(e, e)  # a backslash at a line end continues the line
    return re.sub(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", one, lit, flags=re.S)


# A "/" after one of these (or at the start) begins a regex literal, not a division.
_REGEX_BEFORE = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = ("return", "typeof", "case", "do", "else", "in", "of", "void", "delete", "throw", "yield", "await")


def _starts_regex(src, i):
    k = i - 1
    while k >= 0 and src[k].isspace():
        k -= 1
    if k < 0 or src[k] in _REGEX_BEFORE:
        return True
    word = re.search(r"[A-Za-z_$][\w$]*$", src[:k + 1])
    return bool(word) and word.group(0) in _REGEX_KEYWORDS


def _skip_regex(src, i):
    """The index just past the regex literal that starts at src[i] == "/"; a "/" in a class or escape is not its end."""
    j, n, in_class = i + 1, len(src), False
    while j < n and src[j] != "\n":
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return j + 1
        j += 1
    return i + 1  # not a regex after all; treat the "/" as a character


def _skip_string(src, i):
    """The index just past the quoted string that starts at src[i]."""
    j, n = i + 1, len(src)
    while j < n and src[j] != src[i]:
        j += 2 if src[j] == "\\" else 1
    return j + 1


def _expression_end(src, i):
    """The index of the "}" that closes a template expression whose source starts at src[i]. Braces, strings,
    nested templates, comments and regex literals inside the expression are skipped whole."""
    depth, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i)
            i = n if i < 0 else i + 2
        elif c == "/" and _starts_regex(src, i):
            i = _skip_regex(src, i)
        elif c in "'\"":
            i = _skip_string(src, i)
        elif c == "`":
            i = _template(src, i)[2]
        elif c == "}" and depth == 0:
            return i
        else:
            depth += {"{": 1, "}": -1}.get(c, 0)
            i += 1
    return n


def _template(src, i):
    """The template literal that starts at src[i] == "`": its text pieces, the source of each ${...} expression
    between them (one fewer than the pieces), and the index just past its closing backtick."""
    pieces, exprs, j, n, start = [], [], i + 1, len(src), i + 1
    while j < n and src[j] != "`":
        if src[j] == "\\":
            j += 2
        elif src.startswith("${", j):
            k = _expression_end(src, j + 2)
            pieces.append(src[start:j])
            exprs.append(src[j + 2:k])
            j = start = k + 1
        else:
            j += 1
    pieces.append(src[start:j])
    return pieces, exprs, j + 1


def _template_variants(pieces, exprs):
    """The ways a template can read on screen. An expression's literals may or may not be shown, and a ternary shows
    one branch, so the text is read with every expression dropped, with all literals in place, and with each single
    literal in place of its expression (the others dropped). A phrase that wraps an expression whose literals never
    show (a function argument, the other branch) is still caught by the dropped reading."""
    def fill(choice):
        return "".join(p + choice.get(k, "") for k, p in enumerate(pieces[:-1])) + pieces[-1]
    literals = [[x for x in js_strings(e).split(SENT) if x] for e in exprs]
    variants = [fill({}), fill({k: " ".join(lits) for k, lits in enumerate(literals)})]
    for k, lits in enumerate(literals):
        variants += [fill({k: lit}) for lit in lits]
    return list(dict.fromkeys(variants))


# What may sit between two literals joined by +: spaces, comments and parentheses.
_JOIN = r"(?:\s|/\*.*?\*/|//[^\n]*\n|[()])*\+(?:\s|/\*.*?\*/|//[^\n]*\n|[()])*"


def js_strings(src):
    """The text of the string and template literals of JavaScript source. Literals joined by + become one
    string; every other pair is a separate block. A template is read in each way it can show (see
    _template_variants), and the literals inside its expressions are also blocks of their own. Comments and
    regex literals are skipped."""
    parts, extras, i, n, prev_end = [], [], 0, len(src), None
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i)
            i = n if i < 0 else i + 2
        elif c == "/" and _starts_regex(src, i):
            i = _skip_regex(src, i)
        elif c in "'\"`":
            if c == "`":
                pieces, exprs, end = _template(src, i)
                extras += [js_strings(e) for e in exprs]
                variants = [_js_unescape(v) for v in _template_variants(pieces, exprs)]
            else:
                end = _skip_string(src, i)
                variants = [_js_unescape(src[i + 1:end - 1])]
            if prev_end is not None and re.fullmatch(_JOIN, src[prev_end:i], re.S):
                parts[-1] = [p + v for p in parts[-1] for v in variants]
            else:
                parts.append(variants)
            prev_end = i = end
        else:
            i += 1
    return SENT.join([v for vs in parts for v in dict.fromkeys(vs)] + [e for e in extras if e])


_TAG = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9-]*)((?:[^<>\"']|\"[^\"]*\"|'[^']*')*)>")
_ATTR = re.compile(r"\b(?:title|alt|aria-label|placeholder)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'=<>`]+))", re.I)


def _markup_text(text):
    """Comments dropped; each tag becomes a space, or a block boundary for a block tag (a <wbr> becomes nothing);
    entities decoded. Tags are read before entities are decoded, so an encoded quote inside an attribute value
    does not end it; tags that only appear once entities are decoded (&lt;b&gt;) are stripped too. The values of
    title, alt, aria-label and placeholder, quoted or not, are not part of the visible text: each is a block of
    its own, after the text."""
    values = []

    def tag(m):
        name = m.group(2).lower()
        values.extend(htmllib.unescape(a or b or c) for a, b, c in _ATTR.findall(m.group(3)))
        return "" if name == "wbr" else (SENT if name in _BLOCK_TAGS else " ")
    out = _TAG.sub(tag, re.sub(r"<!--.*?-->", " ", text, flags=re.S))
    out = _TAG.sub(tag, re.sub(r"<!--.*?-->", " ", htmllib.unescape(out), flags=re.S))
    return htmllib.unescape(out) + "".join(SENT + v for v in values)


def _markdown_text(text):
    """Plain text with SENT where a list item, heading, table row or cell, paragraph or code fence ends. A line
    wrap inside one paragraph or one list item is only a space."""
    out = []
    for line in text.split("\n"):
        if not line.strip():
            out.append(SENT)
            continue
        line = re.sub(r"^[ \t]*(?:>[ \t]*)+", "", line)
        # A reference definition (`[1]: url "title"`) is read as a block of its own, never dropped: its title is a
        # tooltip, and a line that only looks like a definition is visible text.
        is_def = re.match(r"^ {0,3}\[[^\]\n]+\]:", line)
        if is_def:
            out.append(SENT)
        if re.match(r"^[ \t]*(?:[-*+]|\d+[.)])[ \t]+", line):
            out.append(SENT)
            line = re.sub(r"^[ \t]*(?:[-*+]|\d+[.)])[ \t]+", "", line)
        if re.match(r"^[ \t]*(?:#{1,6}[ \t]|```|~~~)", line) or re.match(r"^[ \t]*\|", line):
            out.append(SENT)
            line = line.replace("|", SENT) + SENT
        # A link or image shows its text, not its target: `[No one](url) can see` reads as one sentence.
        # A destination or title may hold one level of parentheses: `[No one](https://x/a_(b)) can see`.
        line = re.sub(r"\]\((?:[^()\n]|\([^()\n]*\))*\)", "]", line)
        # A reference link shows only its text: `[No one][1] can see`.
        line = re.sub(r"\]\[[^\]\n]*\]", "]", line)
        # A backslash at the end of a line is a hard break, shown as a line wrap like <br>.
        line = re.sub(r"\\[ \t]*$", "", line)
        out.append(re.sub(r"[*_`~\[\]]", "", line) + (SENT if is_def else " "))
    return "".join(out)


def normalise(rel, text):
    """One line of plain text per file, so a phrase matches however it was written."""
    if rel.endswith(".js"):
        s = js_strings(text)
    elif rel.endswith(".html"):
        scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", text, flags=re.S))
        s = _markup_text(text) + SENT + js_strings(scripts)
    else:
        s = _markdown_text(_markup_text(text))
    s = unicodedata.normalize("NFKC", s).translate(_HYPHENS).translate(_APOSTROPHES).translate(_INVISIBLE)
    return re.sub(r"(?: ?" + SENT + r" ?)+", " " + SENT + " ", " ".join(s.split())).strip()


def _sentence(text, start, end):
    a = max([m.end() for m in re.finditer(r"[.!?]\s|" + SENT, text[:start])] or [0])
    m = re.search(r"[.!?](?:\s|$)|" + SENT, text[end:])
    return text[a:end + (m.end() if m else len(text) - end)]


def _block(text, start, end):
    a = text.rfind(SENT, 0, start) + 1
    b = text.find(SENT, end)
    return a, (len(text) if b < 0 else b)


def find_violations(rel, text, allow, claimed):
    """[(file, offset in the normalised text, rule name, context)] for the hits that no allow entry covers.
    `claimed` maps an allow-entry index to the one block it was used on; a second block is a violation."""
    norm = normalise(rel, text)
    found = []
    for name, rx, _why, only_in in BANNED:
        for m in re.finditer(rx, norm, re.I):
            if only_in and not re.search(only_in, _sentence(norm, m.start(), m.end()), re.I):
                continue
            a, b = _block(norm, m.start(), m.end())
            line = norm[a:b].strip()
            ok = False
            for k, (f, rule, full, _r) in enumerate(allow):
                if f == rel and rule == name and line == normalise(rel, full).replace(SENT, "").strip():
                    if claimed.setdefault(k, a) == a:
                        ok = True
                        break
            if not ok:
                found.append((rel, m.start(), name, norm[max(0, m.start() - 40):m.end() + 40].replace(SENT, " | ")))
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
    used, found = {}, []
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
        allow = [("README.md", "unavailable", "Never say: the pool is unavailable.", "quoted as a banned phrase")]
        self.assertEqual(scan(root, allow), ([], []))
        self.assertEqual([h[2] for h in scan(root, [])[0]], ["unavailable"])

    def test_allow_entry_that_matches_nothing_fails(self):
        root = self.tree({"README.md": "Clean text.\n"})
        allow = [("README.md", "unavailable", "old wording.", "gone")]
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
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no one <b>can</b> see inside</p>\n"}), ["no one can see"])

    def test_phrase_with_html_entities(self):
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no&nbsp;one can &lt;b&gt;see&lt;/b&gt; it</p>\n"}), ["no one can see"])

    def test_phrase_with_js_string_concatenation(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = 'no one ' +\n  \"can see\" + ' it';\n"}), ["no one can see"])

    def test_phrase_with_a_js_template_expression(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `no one ${x}can see it`;\n"}), ["no one can see"])

    def test_phrase_with_a_js_line_continuation(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = 'This pro\\\nves it';\n"}), ["prove"])

    def test_phrase_with_a_js_unicode_escape(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = 'Cathedral\\u2011signed';\n"}), ["Cathedral-signed"])

    def test_phrase_with_a_soft_hyphen_inside_a_word(self):
        self.assertEqual(self.rules({"README.md": "It pro\u00adves it.\n"}), ["prove"])
        self.assertEqual(self.rules({"README.md": "no\u00adone can see it.\n"}), ["no one can see"])

    def test_phrase_in_each_html_attribute(self):
        for attr in ("title", "alt", "aria-label", "placeholder"):
            with self.subTest(attr=attr):
                self.assertEqual(self.rules({"tee/web/p.html": f'<img {attr}="No one can see inside">\n'}), ["no one can see"])
                self.assertEqual(self.rules({"tee/web/p.html": f"<input {attr}='This proves it'>\n"}), ["prove"])

    def test_html_comments_and_other_attributes_are_not_read(self):
        self.assertEqual(self.rules({"tee/web/p.html": '<!-- no one can see -->\n<div class="no one can see" data-x="proof">ok</div>\n'}), [])

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
        # The edited line no longer equals the allowed line, so its quoted phrases fail too; the new claim is among them.
        self.assertTrue(any(h[2] == "prove" and "proves the box is private" in h[3] for h in found), found)

    def test_allow_entry_does_not_silence_a_second_use_of_the_same_rule(self):
        allow = [("README.md", "no one can see", 'Never say "no one can see inside".', "quoted")]
        root = self.tree({"README.md": 'Never say "no one can see inside".\n\nAlso no one can see it.\n'})
        found, _ = scan(root, allow)
        self.assertEqual([h[2] for h in found], ["no one can see"])

    # Review of the merged head: a link target between words, a literal spliced into a template.
    def test_a_markdown_link_target_does_not_split_a_phrase(self):
        self.assertEqual(self.rules({"README.md": "[No one](https://example.com) can see inside.\n"}), ["no one can see"])

    def test_a_literal_spliced_into_a_template_reads_in_place(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `No one ${'can see'} inside`;\n"}), ["no one can see"])

    # Review round 3: template expressions, attributes inside a phrase, <br>, typographic apostrophes.
    def test_string_literals_inside_a_template_expression_are_scanned(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const msg = `${ready ? 'No one can see inside' : 'Waiting'}`;\n"}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/a.js": "const msg = `Status: ${a ? `${b ? \"Cathedral cannot see it\" : ''}` : ''}`;\n"}), ["Cathedral cannot see"])
        self.assertEqual(self.rules({"tee/web/a.js": "const msg = `Ready ${state}.`;\n"}), [])

    def test_an_attribute_inside_a_visible_phrase_does_not_break_it(self):
        self.assertEqual(self.rules({"tee/web/p.html": '<p>No one <span title="Privacy">can</span> see inside</p>\n'}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/p.html": '<p>No one <a href="#" aria-label="more">can</a> see <img alt="x"> inside</p>\n'}), ["no one can see"])

    def test_an_attribute_value_is_its_own_block(self):
        self.assertEqual(self.rules({"tee/web/p.html": '<p title="no one"> can see the list</p>\n'}), [])
        self.assertEqual(self.rules({"tee/web/p.html": '<p title="no one can see">ok</p>\n'}), ["no one can see"])

    def test_an_encoded_quote_or_no_quotes_do_not_end_an_attribute_value(self):
        for markup in ('<p title="He said &quot;hi&quot;, no one can see">ok</p>', "<img alt='It&#39;s proof'>",
                       '<div title=proof>ok</div>', '<input placeholder=Cathedral&#8209;signed>'):
            with self.subTest(markup=markup):
                self.assertEqual(len(self.rules({"tee/web/p.html": markup + "\n"})), 1)

    def test_a_br_is_a_line_wrap_not_a_sentence_end(self):
        for markup in ("<p>No one<br>can see inside</p>", "<p>No one<br/>can see inside</p>", "<p>No one<BR />can see inside</p>"):
            with self.subTest(markup=markup):
                self.assertEqual(self.rules({"tee/web/p.html": markup + "\n"}), ["no one can see"])

    def test_inline_tags_do_not_end_a_sentence(self):
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no one <label>can</label> see inside</p>\n"}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/p.html": "<p>no<wbr>one can see inside</p>\n"}), ["no one can see"])

    def test_block_tags_still_end_a_sentence(self):
        for markup in ("<ul><li>no one</li><li>can see the screen</li></ul>", "<p>no one</p><p>can see it</p>",
                       "<h2>no one</h2><p>can see it</p>", "<table><tr><td>no one</td><td>can see</td></tr></table>",
                       "<div>no one</div><div>can see</div>"):
            with self.subTest(markup=markup):
                self.assertEqual(self.rules({"tee/web/p.html": markup + "\n"}), [])

    def test_typographic_apostrophes_are_the_ascii_apostrophe(self):
        for ap in ("\u2018", "\u2019", "\u02bc", "\uff07", "'"):
            with self.subTest(apostrophe=ap):
                self.assertEqual(self.rules({"README.md": f"Cathedral can{ap}t see the screen.\n"}), ["Cathedral cannot see"])
                self.assertEqual(self.rules({"README.md": f"The host can{ap}t change the software.\n"}), ["host cannot change the software"])

    # Review round 4: a phrase that wraps an expression, a link target with parentheses, a regex literal.
    def test_a_phrase_wrapping_an_expression_whose_literals_do_not_show_fails(self):
        for src in ("const m = `No one ${t('label')} can see inside`;", "const m = `No one ${ok ? 'x' : 'y'} can see inside`;",
                    "const m = `No one ${fmt(a, 'b', 'c')}can see inside`;"):
            with self.subTest(src=src):
                self.assertEqual(self.rules({"tee/web/a.js": src + "\n"}), ["no one can see"])

    def test_an_expression_with_braces_or_a_nested_template_does_not_split_a_phrase(self):
        for src in ("const m = `No one ${fmt({a: 1})} can see inside`;", "const m = `No one ${f(() => { return 1; })} can see inside`;",
                    "const m = `No one ${`inner ${x}`} can see inside`;", "const m = `No one ${'}'} can see inside`;",
                    "const m = `No one ${a.map(x => `<${x}>`).join('')} can see inside`;"):
            with self.subTest(src=src):
                self.assertEqual(self.rules({"tee/web/a.js": src + "\n"}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `ok ${`a ${b}`}`; const n = 'This proves it';\n"}), ["prove"])

    def test_a_ternary_branch_reads_on_its_own(self):
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `No one ${ok ? 'can see' : 'waits'} inside`;\n"}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `No one ${ok ? 'waits' : 'can see'} inside`;\n"}), ["no one can see"])
        self.assertEqual(self.rules({"tee/web/a.js": "const m = `Box ${ok ? 'ready' : 'waiting'}.`;\n"}), [])

    def test_a_markdown_link_target_with_parentheses_does_not_split_a_phrase(self):
        for text in ("[No one](https://en.wikipedia.org/wiki/Box_(computing)) can see inside.\n",
                     '[No one](https://example.com "a (title)") can see inside.\n'):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text}), ["no one can see"])

    def test_a_reference_link_or_a_hard_break_does_not_split_a_phrase(self):
        for text in ("No one can [see][1] inside.\n\n[1]: https://example.com\n", "[no one][x] can see it.\n\n[x]: /a\n",
                     "No one\\\ncan see inside.\n"):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text}), ["no one can see"])
        self.assertEqual(self.rules({"README.md": "[no one]: https://example.com/x\ncan see it\n"}), [])

    def test_a_line_that_only_looks_like_a_reference_definition_is_read(self):
        for text in ("[Note](https://example.com): no one can see inside.\n", "[1]: no one can see inside.\n",
                     "[Note]: https://example.com and no one can see inside.\n", '[1]: https://example.com "No one can see inside"\n',
                     '[1]: https://example.com "No *one* can `see` inside"\n', '[1]: <https://example.com> "No one can see inside"\n'):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text}), ["no one can see"])

    def test_comments_and_parentheses_between_joined_literals(self):
        for src in ("const m = 'No one ' + /* x */ 'can see';", "const m = ('No one ') + ('can see');",
                    "const m = 'No one ' + // x\n  'can see';"):
            with self.subTest(src=src):
                self.assertEqual(self.rules({"tee/web/a.js": src + "\n"}), ["no one can see"])

    def test_a_regex_literal_is_not_a_comment_or_a_string(self):
        for src in ("const r = /[/*]/;\nconst m = 'This proves it';\n", "const r = s.split(/'/);\nconst m = 'This proves it';\n",
                    "const r = /\\/*/g; const m = 'This proves it';\n", "if (x) return /a/.test(y); const m = 'This proves it';\n"):
            with self.subTest(src=src):
                self.assertEqual(self.rules({"tee/web/a.js": src}), ["prove"])
        self.assertEqual(self.rules({"tee/web/a.js": "const h = w / 2 / 'No one can see'.length;\n"}), ["no one can see"])

    # The verbs read and look are banned again; only the frames sentence (S4) is honest.
    def test_cannot_read_and_cannot_look_are_banned(self):
        for text, rule in (("Cathedral cannot read what you type.", "Cathedral cannot see"),
                           ("No one can look inside the box.", "no one can see"),
                           ("Nobody can read your screen.", "no one can see"),
                           ("Cathedral cannot look at the desktop.", "Cathedral cannot see")):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), [rule])

    # Honest text must pass.
    def test_honest_text_passes(self):
        for text in ("The AMD KDS was unavailable.", "It uses proof-of-work.", "Nobody can read the frames without the box key.",
                     "The pool is sold out."):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), [])
        self.assertEqual(self.rules({"tee/web/p.html": "<table><tr><td>pro</td><td>of</td></tr></table>\n"}), [])

    def test_proof_of_work_exemption_is_the_hyphenated_term_only(self):
        for text in ("Every receipt is proof of work done inside a sealed box.", "That is a proof of work."):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), ["proof"])

    def test_unavailable_is_banned_about_capacity(self):
        for text in ("The pool is unavailable.", "The sealed desktop is unavailable right now.", "Capacity is unavailable.",
                     "Rooms are unavailable right now.", "Hotels are unavailable.", "The hotel is unavailable."):
            with self.subTest(text=text):
                self.assertEqual(self.rules({"README.md": text + "\n"}), ["unavailable"])

    # A list item, a table row and a table cell each end a sentence; a hard wrap does not.
    def test_a_list_item_ends_a_sentence(self):
        self.assertEqual(self.rules({"README.md": "- Not until a key: no one\n- Can see the screen of a stopped box.\n"}), [])

    def test_a_table_row_ends_a_sentence(self):
        text = "| Path | Today |\n|---|---|\n| Pool | sealed pool |\n| KDS | AMD KDS: unavailable |\n"
        self.assertEqual(self.rules({"README.md": text}), [])
        self.assertEqual(self.rules({"README.md": "| A | no one |\n| can see | B |\n"}), [])

    def test_a_table_cell_ends_a_sentence(self):
        self.assertEqual(self.rules({"README.md": "| sealed pool | AMD KDS: unavailable |\n"}), [])
        self.assertEqual(self.rules({"README.md": "| no one | can see |\n"}), [])

    def test_a_banned_phrase_wrapped_inside_one_paragraph_or_item_still_fails(self):
        self.assertEqual(self.rules({"README.md": "Today no one\ncan see the box.\n"}), ["no one can see"])
        self.assertEqual(self.rules({"README.md": "- Today no one\n  can see the box.\n"}), ["no one can see"])
        self.assertEqual(self.rules({"README.md": "> Today no one\n> can see the box.\n"}), ["no one can see"])

    # An allow entry covers one line, once.
    def test_a_second_use_of_an_allow_listed_phrase_fails(self):
        with open(os.path.join(ROOT, "tee", "PROMISE.md"), encoding="utf-8") as fh:
            text = fh.read()
        line = '- "Cathedral-signed". The AMD chip vouches for reports (S9).'
        self.assertIn(line, text)
        extra = 'Our reports are "Cathedral-signed".'
        for name, changed in (("appended to the line", text.replace(line, line + " " + extra, 1)),
                              ("as a paragraph at the end", text + "\n" + extra + "\n"),
                              ("as a list item", text.replace(line, line + "\n- " + extra, 1)),
                              ("in a table cell", text.replace("| P5 ", "| " + extra + " | P5 ", 1)),
                              ("the allowed line repeated", text + "\n" + line + "\n")):
            with self.subTest(name):
                found, _ = scan(self.tree({"tee/PROMISE.md": changed}), ALLOW)
                self.assertEqual(sorted({h[2] for h in found}), ["Cathedral-signed"])


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
