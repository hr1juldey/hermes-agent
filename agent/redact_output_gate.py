"""Output-shape gate for ``redact_terminal_output`` (#157915 part 2).

Commands outside the file-read allowlist (``python -c``, ``jq``, ``base64``,
``dd``, …) still print credential stores to the terminal. The command-content
gate in redact.py can never recognise every interpreter, so this gate inspects
the OUTPUT: a line carrying a credential keyword in assignment/JSON shape with
an opaque value is treated as secret-file output and gets the full masking
pass regardless of which command produced it.

False positives here flip source dumps into the masking pass — the exact
regression #138715's negative tests pin — so the triple gate is deliberate:
word-bounded keyword + assignment operator + opaque value (>=16 chars, and
never an ALL-CAPS identifier, a placeholder, or a short literal).
"""
import re

_CRED_KEYWORD = (
    r"(?:access[-_ ]?token|refresh[-_ ]?token|auth[-_ ]?token|session[-_ ]?token|"
    r"api[-_ ]?key|apikey|client[-_ ]?secret|secret|password|passwd|credential[s]?|private[-_ ]?key)"
)
_CRED_VALUE = r'("[^"\n]{16,}"|\'[^\']{16,}\'|[A-Za-z0-9+/_.=-]{16,})'
_CRED_OUTPUT_LINE_RE = re.compile(
    # ``"?``: JSON output quotes the KEY too (``"access_token": "…"``), so the
    # closing quote must not break the keyword→operator chain (#157915).
    rf"\b{_CRED_KEYWORD}\b\"?[ \t]*[:=][ \t]*{_CRED_VALUE}", re.IGNORECASE)
_BARE_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")            # source-code identifiers
_PLACEHOLDER_RE = re.compile(
    r"^\W*(?:\$\{\w+\}?|<[a-z_ -]{2,}>|\*{3,}|\{\{[^}]*\}\})\W*$", re.IGNORECASE)


def output_is_credential_dump(output: str) -> bool:
    """True when ``output`` itself carries a credential-shaped assignment."""
    if not output:
        return False
    for line in output.splitlines():
        m = _CRED_OUTPUT_LINE_RE.search(line)
        if m and not _BARE_CONST_RE.match(m.group(1)) and not _PLACEHOLDER_RE.match(m.group(1)):
            return True
    return False
