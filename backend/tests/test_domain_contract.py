import pytest
from pydantic import ValidationError

from app.models.domain import Asset


def test_asset_contract_is_versioned_and_rejects_unknown_fields() -> None:
    asset = Asset(
        asset_id="asset-1",
        tenant_id="tenant-a",
        display_name="Authorized lab host",
        asset_type="host",
    )

    assert asset.schema_version == "1.0"
    assert asset.model_dump()["schema_version"] == "1.0"

    with pytest.raises(ValidationError):
        Asset(
            asset_id="asset-1",
            tenant_id="tenant-a",
            display_name="Authorized lab host",
            asset_type="host",
            unexpected_field="must be rejected",
        )

