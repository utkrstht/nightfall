import ipaddress
import socket
import asyncio
import pytz
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Optional
from ipwhois import IPWhois
from loguru import logger
from models import IPResponse, ConnectionInfo, FlagInfo, TimezoneInfo
from country_data import COUNTRY_ENRICHMENT

CITY_DB_PATH = "db/city_geolocation.db"

def get_ip_metadata(ip_address: str):
    addr = ipaddress.ip_address(ip_address)
    return "IPv4" if addr.version == 4 else "IPv6"

def get_city_data(ip_address: str) -> Optional[dict]:
    try:
        ip_int = int(ipaddress.IPv4Address(ip_address))
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_abs_path = os.path.join(base_dir, CITY_DB_PATH)
        
        conn = sqlite3.connect(db_abs_path)
        cursor = conn.cursor()
        cursor.execute("SELECT country_code, region, city, latitude, longitude FROM ip_ranges WHERE start_ip_int <= ? AND end_ip_int >= ? LIMIT 1", (ip_int, ip_int))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                "country_code": row[0],
                "region": row[1],
                "city": row[2],
                "latitude": row[3],
                "longitude": row[4]
            }
    except Exception as e:
        logger.error(f"Error fetching city data for {ip_address}: {e}")
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
