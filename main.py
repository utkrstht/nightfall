from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
import ipaddress
import asyncio
import random
import sys
from loguru import logger
from cachetools import TTLCache

from models import IPResponse
from database import init_db, get_cached_data_by_ip, upsert_prefix_cache, get_cached_data_by_prefix, get_prefixes_by_asn, get_all_cached_prefixes
from engine import fetch_live_data, get_ip_metadata, load_city_database

import os

CRAWLER_DELAY = 1.0 
LRU_CACHE_SIZE = 50000

logger.remove()
logger.add(sys.stderr, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:7}</level> | <cyan>{message}</cyan>", level="INFO")
logger.add("db/api.log", rotation="10 MB", retention="7 days")

hot_cache = TTLCache(maxsize=LRU_CACHE_SIZE, ttl=3600)

app = FastAPI(
    title="nightfall",
    description="ip geolocation api",
    version="2.0.0"
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

@app.get("/v1/bulk")
async def bulk_lookup(ips: str):
    ip_list = [ip.strip() for ip in ips.split(",")][:500]
    results = []
    for ip in ip_list:
        try:
            results.append(await get_ip_info(ip))
        except:
            results.append({"ip": ip, "success": False})
    return results

async def database_crawler():
    await asyncio.sleep(5)
    logger.info("Background crawler initialized.")
    backoff = CRAWLER_DELAY

    while True:
        try:
            target_ip = None
            prefixes = await get_all_cached_prefixes()
            
            if prefixes and random.random() < 0.7:
                prefix = random.choice(prefixes)
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if net.version == 4:
                        hosts = list(net.hosts())
                        if hosts:
                            target_ip = str(random.choice(hosts))
                except:
                    pass
            
            if not target_ip:
                major_blocks = [8, 23, 31, 45, 103, 113, 172, 185, 192, 203] 
                o1 = random.choice(major_blocks)
                target_ip = f"{o1}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            cached = await get_cached_data_by_ip(target_ip)
            if not cached:
                live_data = await fetch_live_data(target_ip)
                if live_data.success:
                    prefix = live_data.prefix
                    if prefix:
                        await upsert_prefix_cache(target_ip, prefix, live_data.model_dump())
                    logger.info(f"Crawler found {target_ip} ({live_data.prefix})")
                    backoff = CRAWLER_DELAY
                else:
                    backoff = min(backoff * 2, 300)
                    logger.warning(f"Crawler hit empty zone/limit. Backing off to {backoff}s")
            
            await asyncio.sleep(backoff)
        except Exception as e:
            logger.error(f"Crawler loop fault: {e}")
            await asyncio.sleep(10)

@app.get("/v1/ip/{ip_address}", response_model=IPResponse)
async def get_ip_info_v1(ip_address: str, request: Request):
    return await get_ip_info(ip_address, request)

@app.get("/ip/{ip_address}", response_model=IPResponse)
async def get_ip_info(ip_address: str, request: Request):
    if ":" in ip_address:
        ip_ver = "IPv6"
    else:
        ip_ver = "IPv4"
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if ip_obj.is_private:
        raise HTTPException(status_code=400, detail="Private IP address")

    # Extract behavioral hints from headers
    # We prioritize 'X-Relay' versions if one API is calling another
    user_agent = request.headers.get("x-forwarded-user-agent") or request.headers.get("user-agent", "")
    languages = request.headers.get("x-forwarded-accept-language") or request.headers.get("accept-language", "")
    
    # We pass these hints to the engine for discrepancy analysis
    hints = {
        "user_agent": user_agent,
        "languages": languages
    }

    if ip_address in hot_cache:
        logger.debug(f"LRU HIT for {ip_address}")
        return IPResponse(**hot_cache[ip_address])

    cached = await get_cached_data_by_ip(ip_address)
    if cached:
        logger.debug(f"DB HIT for {ip_address}")
        # Even on DB hit, we could re-validate hints but for efficiency we cache
        hot_cache[ip_address] = cached
        return IPResponse(**cached)

    logger.info(f"Cache MISS, pulling live for {ip_address} ({ip_ver})")
    live_result = await fetch_live_data(ip_address, hints=hints)
    
    if live_result.success:
        data_dict = live_result.model_dump()
        prefix = data_dict.get("prefix")
        if prefix:
            await upsert_prefix_cache(ip_address, prefix, data_dict)
        hot_cache[ip_address] = data_dict
    
    return live_result

@app.get("/v1/asn/{asn}")
async def get_asn_info(asn: int):
    from reputation_data import ASN_REPUTATION
    prefixes = await get_prefixes_by_asn(asn)
    
    asn_key = str(asn)
    reputation_names = {
        "15169": "Google LLC",
        "16509": "Amazon.com, Inc. (AWS)",
        "13335": "Cloudflare, Inc.",
        "8075": "Microsoft Corporation",
        "55836": "Reliance Jio Infocomm Limited",
        "45609": "Bharti Airtel Limited",
        "14061": "DigitalOcean, LLC",
        "20473": "Vultr Holdings, LLC",
        "16276": "OVH SAS",
        "24940": "Hetzner Online GmbH",
        "40021": "M247 Ltd.",
        "396982": "Mullvad VPN AB",
        "60068": "Datacamp Ltd."
    }
    
    org_name = reputation_names.get(asn_key)
    
    if not org_name and prefixes:
        first_data = await get_cached_data_by_prefix(prefixes[0])
        if first_data:
            raw_org = (
                first_data.get("org") or 
                first_data.get("connection", {}).get("org") or 
                first_data.get("isp")
            )
            if raw_org and "Managed Connectivity" not in raw_org:
                org_name = raw_org

    if not org_name:
        org_name = f"ASN {asn} Provider"

    return {
        "asn": f"AS{asn}",
        "organization": org_name,
        "prefixes": prefixes,
        "count": len(prefixes)
    }

@app.on_event("startup")
async def startup():
    os.makedirs("db", exist_ok=True)
    await init_db()
    load_city_database()
    asyncio.create_task(database_crawler())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)
