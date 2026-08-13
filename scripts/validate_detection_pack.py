from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.contracts import DetectionPackManifest, NormalizedRegressionFixture  # noqa: E402
from app.services.detection_framework import DetectionRuleCatalog  # noqa: E402
from app.services.detection_lifecycle import DetectionLifecycleService  # noqa: E402


def main() -> int:
    pack = DetectionPackManifest.model_validate(json.loads((ROOT / "detections/pack.json").read_text()))
    fixtures = [
        NormalizedRegressionFixture.model_validate(item)
        for item in json.loads((ROOT / "detections/fixtures/core.json").read_text())
    ]
    report = DetectionLifecycleService(DetectionRuleCatalog()).run_gate(
        pack,
        fixtures,
        tenant_id="ci-tenant",
        actor="ci-gate",
        dry_run=True,
    )
    print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0 if report.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
