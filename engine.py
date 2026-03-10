import ipaddress
import socket
import asyncio
import pytz
import sqlite3
import os
import bisect
import json
import aiohttp
from datetime import datetime, timezone
from typing import Dict, Optional, List, Tuple
from ipwhois import IPWhois
from loguru import logger
from models import IPResponse, ConnectionInfo, FlagInfo, TimezoneInfo, SecurityInfo
from country_data import COUNTRY_ENRICHMENT
from reputation_data import get_asn_trust_score
from intel_data import (
    VPN_KEYWORDS, HOSTING_KEYWORDS, CRAWLER_KEYWORDS, 
    PROXY_NETWORKS, MOBILE_KEYWORDS, RDNS_PROXY_INDICATORS,
    BOGON_RANGES
)

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

async def fetch_live_data(ip_address: str, hints: Optional[Dict[str, str]] = None) -> IPResponse:
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        for bogon in BOGON_RANGES:
            if ip_obj in ipaddress.ip_network(bogon):
                return IPResponse(
                    ip=ip_address,
                    success=True,
                    type=get_ip_metadata(ip_address),
                    country_code="LO",
                    city="Localhost",
                    security=SecurityInfo(
                        is_vpn=False, is_proxy=False, is_tor=False,
                        is_hosting=False, is_mobile=False, is_crawler=False,
                        is_bogon=True, threat_score=0
                    )
                )
    except:
        pass

    try:
        ripe_url = f"https://stat.ripe.net/data/geoloc/data.json?resource={ip_address}"
        ripe_geo = {"country": None, "city": None, "lat": None, "lon": None}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(ripe_url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        locs = data.get("data", {}).get("located_resources", [])
                        if locs and locs[0].get("locations"):
                            best = locs[0]["locations"][0]
                            ripe_geo["country"] = best.get("country")
                            ripe_geo["city"] = best.get("city")
                            ripe_geo["lat"] = best.get("latitude")
                            ripe_geo["lon"] = best.get("longitude")
            except Exception as e:
                logger.warning(f"RIPE Stat lookup failed: {e}")

        obj = IPWhois(ip_address)
        results = await asyncio.to_thread(obj.lookup_rdap, depth=1)
        
        country_code = ripe_geo["country"] or results.get('asn_country_code')
        asn_desc = results.get('asn_description', "")
        
        postal = None
        if results.get('objects'):
            for obj_key, obj_val in results['objects'].items():
                contact = obj_val.get('contact')
                if not contact: continue
                address = contact.get('address', [])
                if not address: continue
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

        abuse_email = None
        if results.get('objects'):
            for o_key, o_val in results['objects'].items():
                contact = o_val.get('contact', {})
                emails = contact.get('email', [])
                if emails:
                    abuse_email = emails[0].get('value')
                    break

        asn_raw = results.get('asn')
        asn_clean = None
        if asn_raw:
            try:
                asn_str = "".join(filter(str.isdigit, str(asn_raw)))
                if asn_str:
                    asn_clean = int(asn_str)
            except (ValueError, TypeError):
                pass
        
        asn_lower = asn_desc.lower()

        final_country = country_code
        final_city = None
        is_hosting_suggested = False
        is_mobile = any(word in asn_lower for word in MOBILE_KEYWORDS)
        
        host_domain = results.get('network', {}).get('name', '').lower()
        if any(word in host_domain for word in ["datapacket", "datacamp", "oxylabs", "brightdata", "smartproxy", "iproyal", "soax", "luminati", "packetstream", "stormproxies", "geosurf", "netnut"]):
            is_hosting_suggested = True

        if results.get('objects'):
            for obj_key, obj_val in results['objects'].items():
                contact = obj_val.get('contact')
                if not contact: continue
                
                contact_str = json.dumps(contact).lower()
                
                if any(word in contact_str for word in ["singapore", " sg"]):
                    final_country = "SG"
                    final_city = "Singapore"
                    break
                if any(word in contact_str for word in ["london", " united kingdom"]):
                    final_country = "GB"
                    final_city = "London"
                    break
                
                address = contact.get('address', [])
                if not address: continue
                full_addr_text = " ".join([a.get('value', '').lower() for a in address])
                if any(word in full_addr_text for word in ["singapore", " sg"]):
                    final_country = "SG"
                    final_city = "Singapore"
                    break

        is_hosting = is_hosting_suggested or any(word in asn_lower for word in HOSTING_KEYWORDS)
        
        rdns = ""
        try:
            rdns = await asyncio.to_thread(socket.getfqdn, ip_address)
            rdns = rdns.lower()
        except:
            pass

        is_vpn = (
            any(word in asn_lower for word in VPN_KEYWORDS) or 
            any(word in host_domain for word in ["vpn", "proxy"] + VPN_KEYWORDS) or
            any(word in rdns for word in ["vpn", "proxy", "unn-", "exit-node", "tunnel", "vps-", "node-", "relay-"] + VPN_KEYWORDS)
        )

        if not is_vpn and (is_hosting or is_hosting_suggested):
            if any(word in asn_lower or word in host_domain or word in rdns for word in VPN_KEYWORDS):
                is_vpn = True

        is_tor = any(word in asn_lower or word in rdns for word in ["tor-exit", "tor exit", "onion", "torproject"])
        is_crawler = any(word in asn_lower or word in rdns for word in CRAWLER_KEYWORDS)
        
        is_discrepancy = False
        if hints:
            langs = hints.get("languages", "").lower()
            if langs and final_country:
                country_code_lower = final_country.lower()
                if country_code_lower not in langs and any(c in "abcdefghijklmnopqrstuvwxyz" for c in langs[:2]):
                    is_discrepancy = True
            
            ua = hints.get("user_agent", "").lower()
            if any(bot in ua for bot in ["curl", "python", "go-http", "wget", "headless"]):
                is_crawler = True

        isp_name = asn_desc
        org_name = asn_desc
        
        
        if is_hosting:
            conn_type = "hosting"
            is_vpn = True
            found_hosting = next((word.capitalize() for word in HOSTING_KEYWORDS if word in asn_lower), None)
            if found_hosting: isp_name = found_hosting
        elif is_vpn:
            conn_type = "vpn"
            is_hosting = True 
        elif is_mobile:
            conn_type = "mobile"
        else:
            conn_type = "residential"
            found_isp = next((word.capitalize() for word in ["comcast", "at&t", "verizon", "t-mobile"] if word in asn_lower), None)
            if found_isp: isp_name = found_isp

        prefix = None
        if results.get('network'):
            prefix = results['network'].get('cidr')

        city_data = None
        try:
            city_data = await asyncio.to_thread(get_city_data, ip_address)
        except:
            pass

        raw_trust = get_asn_trust_score(asn_clean or 0, is_vpn, is_hosting)
        if is_tor: raw_trust += 30
        if is_discrepancy: raw_trust += 15
        if is_crawler: raw_trust += 10
        
        final_threat_score = min(max(raw_trust, 0), 100)

        response = IPResponse(
            ip=ip_address,
            success=True,
            type=get_ip_metadata(ip_address),
            country_code=ripe_geo["country"] or final_country or (city_data['country_code'] if city_data else None),
            prefix=prefix,
            region=city_data['region'] if city_data else None,
            city=ripe_geo["city"] or final_city or (city_data['city'] if city_data else None),
            latitude=ripe_geo["lat"] or (city_data['latitude'] if city_data else None),
            longitude=ripe_geo["lon"] or (city_data['longitude'] if city_data else None),
            postal=postal,
            connection=ConnectionInfo(
                asn=asn_clean,
                org=org_name,
                isp=isp_name,
                type=conn_type
            ),
            security=SecurityInfo(
                is_vpn=is_hosting,
                #is_proxy=is_hosting,
                is_tor=is_tor,
                #is_hosting=is_hosting,
                is_mobile=is_mobile,
                is_crawler=is_crawler,
                is_bogon=False,
                is_discrepancy=is_discrepancy,
                abuse_email=abuse_email,
                threat_score=final_threat_score,
                threat_level="high" if final_threat_score > 70 else "medium" if final_threat_score > 30 else "low"
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
