from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.schemas.contracts import AssetObservation, ReconCommand, ReconResult
from app.services.authorized_scan import (
    AuthorizationError,
    AuthorizedScanService,
    AuthorizedScope,
)


def _scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "scope_id": "LAB-2026-0001",
                "allowed_cidrs": ["192.168.56.0/24"],
                "allowed_web_origins": ["https://app.lab.example"],
                "max_targets": 1,
                "max_web_paths": 2,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_authorized_scan_dry_run_is_scope_bound_and_audited(tmp_path: Path) -> None:
    service = AuthorizedScanService(AuthorizedScope.from_file(_scope_file(tmp_path)))
    audit_file = tmp_path / "audit.jsonl"
    report = service.run(
        "192.168.56.10",
        authorization_id="CHG-2026-0001",
        operator="security.analyst",
        audit_file=audit_file,
    )
    assert report.dry_run is True
    assert report.recon.commands[0].executed is False
    record = json.loads(audit_file.read_text(encoding="utf-8"))
    assert record["scope_id"] == "LAB-2026-0001"
    assert record["authorization_id"] == "CHG-2026-0001"
    assert oct(audit_file.stat().st_mode & 0o777) == "0o600"


def test_authorized_scan_rejects_out_of_scope_target(tmp_path: Path) -> None:
    service = AuthorizedScanService(AuthorizedScope.from_file(_scope_file(tmp_path)))
    with pytest.raises(Exception, match="outside the configured lab scope"):
        service.run(
            "8.8.8.8",
            authorization_id="CHG-2026-0001",
            operator="security.analyst",
            audit_file=tmp_path / "audit.jsonl",
        )


def test_candidates_are_inventory_correlations_not_exploits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = AuthorizedScanService(AuthorizedScope.from_file(_scope_file(tmp_path)))

    def fake_run(*args: object, **kwargs: object) -> ReconResult:
        return ReconResult(
            scan_id="scan-1",
            dry_run=False,
            targets=["192.168.56.10"],
            commands=[
                ReconCommand(
                    tool="nmap",
                    argv=["nmap", "192.168.56.10"],
                    purpose="approved inventory",
                    executed=True,
                )
            ],
            assets=[AssetObservation(ip="192.168.56.10", services=["https", "ssh"])],
        )

    monkeypatch.setattr(service.recon, "run", fake_run)
    report = service.run(
        "192.168.56.10",
        authorization_id="CHG-2026-0001",
        operator="security.analyst",
        execute=True,
        audit_file=tmp_path / "audit.jsonl",
    )
    assert {candidate.service for candidate in report.candidates} == {"https", "ssh"}
    assert all(candidate.requires_validation for candidate in report.candidates)
    assert all("exploit" not in candidate.rationale.lower() for candidate in report.candidates)


def test_web_origin_must_be_explicitly_approved(tmp_path: Path) -> None:
    scope = AuthorizedScope.from_file(_scope_file(tmp_path))
    with pytest.raises(AuthorizationError, match="outside the approved scope origins"):
        scope.validate_web_origin("https://outside.example")


def test_web_inventory_is_bounded_to_approved_origin_and_path_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = AuthorizedScanService(AuthorizedScope.from_file(_scope_file(tmp_path)))
    requested_urls: list[str] = []

    class FakeResponse:
        status_code = 200
        headers = {"content-length": "42"}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["follow_redirects"] is False

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str) -> FakeResponse:
            requested_urls.append(url)
            return FakeResponse()

    monkeypatch.setattr("app.services.authorized_scan.httpx.Client", FakeClient)
    observations, warnings = service._enumerate_web("https://app.lab.example")
    assert warnings == []
    assert requested_urls == ["https://app.lab.example/", "https://app.lab.example/robots.txt"]
    assert [observation.status_code for observation in observations] == [200, 200]
