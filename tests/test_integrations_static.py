from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import yaml

from integrations.openclaw.profile_adapter import OpenClawRequest, VMGAOpenClawProfileAdapter
from integrations.hermes import schemas
from integrations.hermes import tools as hermes_tools


ROOT = Path(__file__).resolve().parents[1]


class _FakeBrokerResponse:
    def __init__(self, body: bytes | str):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _read_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_hermes_manifest_declares_expected_tools_only():
    manifest = yaml.safe_load((ROOT / "integrations" / "hermes" / "plugin.yaml").read_text(encoding="utf-8"))

    assert manifest["name"] == "vmga-mail"
    assert manifest["requires_env"][0]["name"] == "VMGA_BROKER_URL"
    assert manifest["provides_tools"] == [
        "mail_search",
        "mail_get",
        "mail_get_attachment",
        "mail_create_draft",
        "mail_send",
    ]


def test_hermes_schemas_define_v5_tools():
    names = {
        schemas.MAIL_SEARCH["name"],
        schemas.MAIL_GET["name"],
        schemas.MAIL_GET_ATTACHMENT["name"],
        schemas.MAIL_CREATE_DRAFT["name"],
        schemas.MAIL_SEND["name"],
    }
    assert names == {
        "mail_search",
        "mail_get",
        "mail_get_attachment",
        "mail_create_draft",
        "mail_send",
    }


def test_hermes_handler_returns_json_and_posts_to_broker():
    captured: Dict[str, Any] = {}

    def fake_urlopen(req, timeout=None):
        captured.update(
            {
                "url": req.full_url,
                "auth": req.headers.get("Authorization"),
                "payload": json.loads(req.data.decode("utf-8")) if req.data else {},
            }
        )
        return _FakeBrokerResponse(b'{"status":"OK"}')

    with patch("integrations.hermes.tools.request.urlopen", fake_urlopen):
        output = json.loads(
            hermes_tools.mail_search(
                {"query": "from:test@example.com", "max_results": 7},
                broker_url="https://vmga.example.invalid",
                broker_token="broker-token",
            )
        )

    assert output["status"] == "OK"
    assert output["tool"] == "mail_search"
    assert captured["url"] == "https://vmga.example.invalid/v1/proposals"
    assert captured["auth"] == "Bearer broker-token"
    assert captured["payload"]["action"] == "read"
    assert captured["payload"]["search_query"] == "from:test@example.com"


def test_hermes_handler_fails_closed_when_broker_is_missing():
    output = json.loads(hermes_tools.mail_get({"message_id": "m1"}))
    assert output["status"] == "DENY"
    assert output["error_code"] == "vmga_broker_missing"


def test_hermes_handler_fails_closed_on_invalid_payload():
    output = json.loads(hermes_tools.mail_send("not-json", broker_url="https://vmga.example.invalid"))
    assert output["status"] == "DENY"
    assert output["error_code"] == "vmga_invalid_payload"


def test_hermes_handler_fails_closed_for_broker_invalid_json():
    with patch("integrations.hermes.tools.request.urlopen", lambda _req, timeout=None: _FakeBrokerResponse("not-json")):
        output = json.loads(
            hermes_tools.mail_get(
                {"message_id": "m1"},
                broker_url="https://vmga.example.invalid",
            )
        )

    assert output["status"] == "DENY"
    assert output["error_code"] == "vmga_broker_bad_json"


def test_hermes_handlers_do_not_dispatch_terminal_or_native_gmail_paths():
    source = (ROOT / "integrations" / "hermes" / "tools.py").read_text(encoding="utf-8")
    forbidden = ["dispatch_tool", "terminal", "gmail", "subprocess", "os.system", "os.popen"]
    for token in forbidden:
        assert token not in source


def test_openclaw_manifest_and_route_contract():
    manifest = json.loads((ROOT / "integrations" / "openclaw" / "openclaw.plugin.json").read_text(encoding="utf-8"))

    assert manifest["id"] == "plugin.vmga"
    assert "broker_token" in manifest["configSchema"]["properties"]
    assert "broker_timeout_seconds" in manifest["configSchema"]["properties"]
    assert manifest["contracts"]["tools"] == [
        "mail_search",
        "mail_get",
        "mail_get_attachment",
        "mail_create_draft",
        "mail_send",
    ]


def test_openclaw_adapter_maps_tools_and_blocks_disallowed_paths():
    adapter = VMGAOpenClawProfileAdapter("https://vmga.example.invalid")

    assert adapter.map_tool("mail_search") == "read"
    assert adapter.map_tool("mail_get_attachment") == "download_attachment"

    result = adapter.execute(OpenClawRequest(tool_id="gmail.send", payload={}))
    assert result["status"] == "DENY"
    assert result["error_code"] == "vmga_tool_denied"


def test_openclaw_adapter_posts_to_broker_with_expected_payload_shape():
    captured: Dict[str, Any] = {}

    def fake_urlopen(req, timeout=None):
        captured.update(
            {
                "url": req.full_url,
                "auth": req.headers.get("Authorization"),
                "payload": json.loads(req.data.decode("utf-8")),
            }
        )
        return _FakeBrokerResponse(b'{"status":"OK"}')

    request = OpenClawRequest(
        tool_id="mail_send",
        actor_id="openclaw-operator",
        payload={
            "recipients": ["a@example.com", "b@example.com"],
            "subject": "Test",
            "content": "hello",
            "message_ids": ["m1"],
            "message_id": "m2",
        },
    )

    with patch("integrations.openclaw.profile_adapter.urllib_request.urlopen", fake_urlopen):
        output = VMGAOpenClawProfileAdapter("https://vmga.example.invalid", bearer_token="broker-token").execute(request)

    assert output["status"] == "OK"
    assert output["tool"] == "mail_send"
    assert captured["url"] == "https://vmga.example.invalid/v1/proposals"
    assert captured["auth"] == "Bearer broker-token"
    assert captured["payload"]["action"] == "send"
    assert captured["payload"]["actor_id"] == "openclaw-operator"


def test_openclaw_example_does_not_allow_gmail_workspace_direct_paths():
    config = _read_yaml(ROOT / "examples" / "openclaw_gateway_vmga.yaml")

    deny_prefixes = config["security"]["deny_tool_prefixes"]
    assert "gmail" in deny_prefixes
    assert "gws" in deny_prefixes
    assert "workspace" in deny_prefixes
    assert "terminal" in deny_prefixes
    assert "browser" in deny_prefixes

    metadata = config["static_metadata"]
    assert metadata["route_only_through_broker"] is True


def test_examples_dont_contain_real_secrets():
    secret_patterns = [
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bASIA[0-9A-Z]{16}\b"),
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b"),
        re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
        re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----"),
    ]

    for path in [
        ROOT / "examples" / "hermes_vmga_plugin.yaml",
        ROOT / "examples" / "openclaw_gateway_vmga.yaml",
    ]:
        content = path.read_text(encoding="utf-8")
        for pattern in secret_patterns:
            assert not pattern.search(content)


def test_examples_reference_placeholder_broker_urls_only():
    hermes = _read_yaml(ROOT / "examples" / "hermes_vmga_plugin.yaml")
    openclaw = _read_yaml(ROOT / "examples" / "openclaw_gateway_vmga.yaml")

    assert hermes["hermes_plugin"]["broker_default"]["url"] == "https://vmga.example.invalid"
    assert openclaw["vmga"]["broker_url"] == "https://vmga.example.invalid"


def test_runtime_docs_distinguish_plugin_loaded_from_gateway_ready():
    openclaw_doc = (ROOT / "docs" / "openclaw_integration.md").read_text(encoding="utf-8")
    hermes_doc = (ROOT / "docs" / "hermes_integration.md").read_text(encoding="utf-8")

    assert "Local Gateway Readiness" in openclaw_doc
    assert "plugin.vmga` being loaded proves only" in openclaw_doc
    assert "openclaw doctor" in openclaw_doc
    assert "Runtime Verification" in hermes_doc
    assert "VMGA_BROKER_TOKEN" in hermes_doc
