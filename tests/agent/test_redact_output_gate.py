"""#157915 part 2: the output-shape credential gate for non-allowlisted readers.

``redact_terminal_output`` only ran the ENV/YAML/JSON assignment passes when the
*command* was an env dump or an allowlisted file reader, so ``python3 -c``,
``jq``, ``dd`` and ``base64`` printed credential stores verbatim. The gate must
fold into the ``secret_file=`` decision so the masking passes run regardless of
which command produced the output.

Base truth pinned at origin/main f6c3eb1a: the ``cat ~/.hermes/auth.json``
filename classification does NOT exist there (that is part 1, PR #158145) — the
filename half only masks the ``eyJ`` JWT via the prefix pass while the
prefix-less ``refresh_token`` value leaks. These tests pin the output-gate
half: the same line must mask under any command, including ``None``.
"""
import pytest

from agent.redact_output_gate import output_is_credential_dump
from agent.redact import redact_terminal_output


AUTH_JSON_LINE = ('{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9-mm-tok-0123456789", '
                  '"refresh_token": "r3fr3sh-t0k3n-value-001234567890"}')
REFRESH_VALUE = "r3fr3sh-t0k3n-value-001234567890"
YAML_LINE = "refresh_token: 0AUTH_C0NTENT_VALUE_1234567890ABCDEF"


@pytest.fixture(autouse=True)
def _ensure_redaction_enabled(monkeypatch):
    """Mirror tests/agent/test_redact.py: redaction must be on regardless of env."""
    monkeypatch.delenv("HERMES_REDACT_SECRETS", raising=False)
    monkeypatch.setattr("agent.redact._REDACT_ENABLED", True)


@pytest.mark.parametrize("command", [
    "python3 -c 'import json;print(open(...).read())'",
    "jq .",
    "dd if=...",
    "base64 -d",
    None,
])
def test_gate_masks_credential_output_from_any_reader(command):
    out = redact_terminal_output(AUTH_JSON_LINE + "\n", command)
    # The prefix pass already head/tail-masks the JWT; the prefix-less
    # refresh_token value is what leaked verbatim at base (#157915).
    assert REFRESH_VALUE not in out
    assert "001234567890" not in out
    assert out != AUTH_JSON_LINE + "\n"


def test_yaml_shape_masked():
    out = redact_terminal_output(YAML_LINE + "\n", "python3 -c x")
    assert "0AUTH_C0NTENT_VALUE_1234567890ABCDEF" not in out


def test_env_dump_control_unchanged():
    """The allowlisted env-dump path already masked; the gate must not regress it."""
    out = redact_terminal_output(AUTH_JSON_LINE + "\n", "env")
    assert REFRESH_VALUE not in out


def test_secret_file_reader_composes_with_gate():
    """At base, ``cat ~/.hermes/auth.json`` is NOT filename-classified (part 1 is
    PR #158145, unmerged) and the refresh_token leaked. The output gate must mask
    it anyway — composing with, not depending on, the filename half."""
    out = redact_terminal_output(AUTH_JSON_LINE + "\n", "cat ~/.hermes/auth.json")
    assert REFRESH_VALUE not in out


def test_source_preserving_negatives():
    for line in (
        "max_tokens: 100",
        'api_key = MY_PROVIDER_CONSTANT_NAME',          # bare ALL-CAPS identifier, not a secret
        'password = "short"',                            # below the 16-char opacity floor
        "tokenizer: cl100k_base",
        'API_KEY = "${API_KEY}"',                        # placeholder
        "password: <your-token-here>",                   # placeholder
    ):
        assert output_is_credential_dump(line) is False, line
        assert redact_terminal_output(line + "\n", "grep -r pattern src/") == line + "\n"


def test_gate_classifier_positives():
    assert output_is_credential_dump(AUTH_JSON_LINE) is True
    assert output_is_credential_dump(YAML_LINE) is True
    assert output_is_credential_dump("") is False
    assert output_is_credential_dump("no secrets on this line\nnor this one") is False
