"""
Pydantic models for Splunk ES API responses.
"""
from pydantic import BaseModel, Field
from typing import List, Optional

class SplunkAlert(BaseModel):
    """
    Pydantic model for a single Splunk alert.
    """
    time: str = Field(..., alias='_time')
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    signature: Optional[str] = None
    rule_name: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    raw: str = Field(..., alias='_raw')

class SplunkSearchResponse(BaseModel):
    """
    Pydantic model for the Splunk search/jobs API response.
    """
    results: List[SplunkAlert]
