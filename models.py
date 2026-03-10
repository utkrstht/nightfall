from pydantic import BaseModel, Field
from typing import Optional, Dict

class FlagInfo(BaseModel):
    img: str = Field(..., description="URL to the country flag SVG")
    emoji: str = Field(..., description="Country flag emoji")
    emoji_unicode: str = Field(..., description="Unicode representation of the flag emoji")

class ConnectionInfo(BaseModel):
    asn: Optional[int] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    type: Optional[str] = "residential"
    domain: Optional[str] = None
    abuse_email: Optional[str] = None

class SecurityInfo(BaseModel):
    is_vpn: bool = False
    is_tor: bool = False
    is_crawler: bool = False
    #is_proxy: bool = False
    is_mobile: bool = False
    #is_hosting: bool = False  Commented out, as hosting/proxy are now considered VPNs
    is_bogon: bool = False
    is_discrepancy: bool = False
    threat_score: int = 0
    threat_level: str = "low"
    abuse_email: Optional[str] = None
    fingerprint: Optional[str] = None

class TimezoneInfo(BaseModel):
    id: str
    abbr: str
    is_dst: bool
    offset: int
    utc: str

class IPResponse(BaseModel):
    ip: str
    success: bool
    type: str
    prefix: Optional[str] = None
    continent: Optional[str] = None
    continent_code: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    postal: Optional[str] = None
    calling_code: Optional[str] = None
    capital: Optional[str] = None
    borders: Optional[str] = None
    flag: Optional[FlagInfo] = None
    connection: Optional[ConnectionInfo] = None
    security: Optional[SecurityInfo] = None
    timezone: Optional[TimezoneInfo] = None
    last_updated: Optional[str] = None
