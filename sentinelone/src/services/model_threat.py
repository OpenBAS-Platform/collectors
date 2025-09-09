"""SentinelOne Threat Models.

This module provides Pydantic models for threat operations.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, PrivateAttr


class SentinelOneThreat(BaseModel):
    """SentinelOne threat model."""

    threat_id: str = Field(..., description="Unique identifier for the threat")
    _raw: Optional[dict[str, Any]] = PrivateAttr(default=None)


class SentinelOneThreatsResponse(BaseModel):
    """Response from threats endpoint."""

    data: list[SentinelOneThreat] = Field(
        default_factory=list, description="List of SentinelOne threats"
    )

    @classmethod
    def from_raw_response(
        cls, response_data: dict[str, Any]
    ) -> "SentinelOneThreatsResponse":
        """Create from raw API response.

        Args:
            response_data: Raw response data from the threats API.

        Returns:
            SentinelOneThreatsResponse instance with parsed threats.

        """
        threats = []
        raw_threats = response_data.get("data", [])

        for raw_threat in raw_threats:
            threat_id = None
            if raw_threat.get("threatInfo") and raw_threat["threatInfo"].get(
                "threatId"
            ):
                threat_id = raw_threat["threatInfo"]["threatId"]

            if threat_id:
                threat = SentinelOneThreat(threat_id=threat_id, _raw=raw_threat)
                threats.append(threat)

        return cls(data=threats)
