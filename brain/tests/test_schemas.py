import json
import re
from pathlib import Path

from jsonschema import validate


def test_fixtures_match_schemas() -> None:
    base = Path("contracts")
    request_schema = json.loads((base / "schemas" / "tool_request.schema.json").read_text())
    response_schema = json.loads((base / "schemas" / "tool_response.schema.json").read_text())
    http_request_schema = json.loads((base / "schemas" / "http_verify_request.schema.json").read_text())
    http_response_schema = json.loads((base / "schemas" / "http_verify_response.schema.json").read_text())

    request_fixture = json.loads((base / "fixtures" / "probe_request.json").read_text())
    response_fixture = json.loads((base / "fixtures" / "probe_response.json").read_text())
    http_request_fixture = json.loads((base / "fixtures" / "http_verify_request.json").read_text())
    http_response_fixture = json.loads((base / "fixtures" / "http_verify_response.json").read_text())

    validate(instance=request_fixture, schema=request_schema)
    validate(instance=response_fixture, schema=response_schema)
    validate(instance=http_request_fixture, schema=http_request_schema)
    validate(instance=http_response_fixture, schema=http_response_schema)


def test_fixture_versions_are_consistent() -> None:
    probe_response = json.loads(Path("contracts/fixtures/probe_response.json").read_text())
    http_response = json.loads(Path("contracts/fixtures/http_verify_response.json").read_text())

    probe_version = probe_response["tool_version"]
    http_version = http_response["tool_version"]

    assert probe_version == http_version
    assert re.match(r"^\d+\.\d+\.\d+(?:[-+].+)?$", probe_version)
