import ipaddress
import socket
import asyncio
import pytz
import sqlite3
import os
import bisect
from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple
from ipwhois import IPWhois
from loguru import logger
from models import IPResponse, ConnectionInfo, FlagInfo, TimezoneInfo
from country_data import COUNTRY_ENRICHMENT

CITY_DB_PATH = "db/city_geolocation.db"

_city_index: List[Tuple[int, int, dict]] = []
_city_starts: List[int] = []

def load_city_database():
    global _city_index, _city_starts
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_abs_path = os.path.join(base_dir, CITY_DB_PATH)
        if not os.path.exists(db_abs_path):
            logger.warning("City database not found.")
            return

        conn = sqlite3.connect(db_abs_path)
        cursor = conn.cursor()
        cursor.execute("SELECT start_ip_int, end_ip_int, country_code, region, city, latitude, longitude FROM ip_ranges ORDER BY start_ip_int")
        rows = cursor.fetchall()
        
        _city_index = [(r[0], r[1], {"country_code": r[2], "region": r[3], "city": r[4], "latitude": r[5], "longitude": r[6]}) for r in rows]
        _city_starts = [r[0] for r in _city_index]
        conn.close()
        logger.info(f"Loaded {len(_city_index)} prefix ranges into memory.")
    except Exception as e:
        logger.error(f"Failed to load city database: {e}")

def get_ip_metadata(ip_address: str):
    return "IPv6" if ":" in ip_address else "IPv4"

def get_city_data(ip_address: str) -> Optional[dict]:
    if ":" in ip_address or not _city_index:
        return None
    try:
        ip_int = int(ipaddress.IPv4Address(ip_address))
        idx = bisect.bisect_right(_city_starts, ip_int) - 1
        if idx >= 0:
            start, end, data = _city_index[idx]
            if start <= ip_int <= end:
                return data
    except Exception as e:
        logger.error(f"Error in memory lookup: {e}")
    return None

def generate_flag_data(country_code: str) -> Dict[str, str]:
    if not country_code or len(country_code) != 2:
        return {"img": "", "emoji": "", "emoji_unicode": ""}
    emoji = "".join(chr(ord(c) + 127397) for c in country_code.upper())
    unicode_str = " ".join(f"U+{ord(c):X}" for c in emoji)
    return {
        "img": f"https://cdn.ipwhois.io/flags/{country_code.lower()}.svg",
        "emoji": emoji,
        "emoji_unicode": unicode_str
    }

async def fetch_live_data(ip_address: str) -> IPResponse:
    try:
        obj = IPWhois(ip_address)
        results = await asyncio.to_thread(obj.lookup_rdap, depth=1)
        
        country_code = results.get('asn_country_code')
        asn_desc = results.get('asn_description', "")
        
        postal = None
        if results.get('objects'):
            for obj_key, obj_val in results['objects'].items():
                contact = obj_val.get('contact', {})
                address = contact.get('address', [])
                for addr in address:
                    val = addr.get('value', '')
                    if val:
                        parts = val.split('\n')
                        for part in parts:
                            cleaned = part.strip()
                            if cleaned.isdigit() and len(cleaned) >= 5:
                                postal = cleaned
                                break
                    if postal: break
                if postal: break

        asn_raw = results.get('asn')
        asn_clean = None
        if asn_raw:
            try:
                asn_str = "".join(filter(str.isdigit, str(asn_raw)))
                if asn_str:
                    asn_clean = int(asn_str)
            except (ValueError, TypeError):
                pass

        is_hosting = any(word in asn_desc.lower() for word in ["amazon", "google", "cloudflare", "digitalocean", "hetzner", "ovh", "akamai", "microsoft", "azure"])
        conn_type = "hosting" if is_hosting else "residential"

        prefix = None
        if results.get('network'):
            prefix = results['network'].get('cidr')

        city_data = None
        try:
            city_data = await asyncio.to_thread(get_city_data, ip_address)
        except:
            pass

        response = IPResponse(
            ip=ip_address,
            success=True,
            type=get_ip_metadata(ip_address),
            country_code=country_code or (city_data['country_code'] if city_data else None),
            prefix=prefix,
            region=city_data['region'] if city_data else None,
            city=city_data['city'] if city_data else None,
            latitude=city_data['latitude'] if city_data else None,
            longitude=city_data['longitude'] if city_data else None,
            postal=postal,
            connection=ConnectionInfo(
                asn=asn_clean,
                org=asn_desc,
                isp=asn_desc,
                type=conn_type
            )
        )

        country_code = response.country_code
        if country_code in COUNTRY_ENRICHMENT:
            enrich = COUNTRY_ENRICHMENT[country_code].copy()
            coords = enrich.pop("lat_lng", None)
            
            if coords and response.latitude is None:
                response.latitude, response.longitude = coords[0], coords[1]
            
            if "name" in enrich:
                response.country = enrich.pop("name")
                
            for key, val in enrich.items():
                if hasattr(response, key):
                    setattr(response, key, val)

        if country_code:
            response.flag = FlagInfo(**generate_flag_data(country_code))
            try:
                tz_names = pytz.country_timezones.get(country_code)
                if tz_names:
                    tz_name = tz_names[0]
                    tz = pytz.timezone(tz_name)
                    now = datetime.now(tz)
                    response.timezone = TimezoneInfo(
                        id=tz_name, abbr=now.strftime('%Z'), is_dst=bool(now.dst()),
                        offset=int(now.utcoffset().total_seconds()), utc=now.strftime('%z')
                    )
            except: pass

        try:
            hostname, _, _ = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip_address),
                timeout=2.0
            )
            response.connection.domain = hostname
        except: pass

        response.last_updated = datetime.now(timezone.utc).isoformat()
        return response

    except Exception as e:
        logger.error(f"Failed live pull for {ip_address}: {e}")
        return IPResponse(ip=ip_address, success=False, type=get_ip_metadata(ip_address))
