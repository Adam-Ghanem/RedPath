from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Asset(BaseModel):
    """Versioned, strict shared asset contract used by RedPath integrations."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    asset_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(min_length=1, max_length=64)
