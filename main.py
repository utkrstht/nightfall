from fastapi import FastAPI, HTTPException
import ipaddress
import asyncio
import random
import sys
from loguru import logger
from cachetools import TTLCache

from models import IPResponse
from database import init_db, get_cached_data_by_ip, upsert_prefix_cache, get_cached_data_by_prefix, get_prefixes_by_asn
from engine import fetch_live_data, get_ip_metadata

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

async def database_crawler():
    await asyncio.sleep(5)
    logger.info("Background crawler initialized.")
    backoff = CRAWLER_DELAY

    while True:
        try:
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
async def get_ip_info_v1(ip_address: str):
    return await get_ip_info(ip_address)

@app.get("/ip/{ip_address}", response_model=IPResponse)
async def get_ip_info(ip_address: str):
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

    if ip_address in hot_cache:
        logger.debug(f"LRU HIT for {ip_address}")
        return IPResponse(**hot_cache[ip_address])

    cached = await get_cached_data_by_ip(ip_address)
    if cached:
        logger.debug(f"DB HIT for {ip_address}")
        hot_cache[ip_address] = cached
        return IPResponse(**cached)

    logger.info(f"Cache MISS, pulling live for {ip_address} ({ip_ver})")
    live_result = await fetch_live_data(ip_address)
    
    if live_result.success:
        data_dict = live_result.model_dump()
        prefix = data_dict.get("prefix")
        if prefix:
            await upsert_prefix_cache(ip_address, prefix, data_dict)
        hot_cache[ip_address] = data_dict
    
    return live_result

@app.get("/v1/asn/{asn}")
async def get_asn_info(asn: int):
    prefixes = await get_prefixes_by_asn(asn)
    
    org_name = "Unknown"
    if prefixes:
        first_data = await get_cached_data_by_prefix(prefixes[0])
        if first_data:
            org_name = first_data.get("connection", {}).get("org", "Unknown")

    return {
        "asn": f"AS{asn}",
        "organization": org_name,
        "prefixes": prefixes,
        "count": len(prefixes)
    }

@app.on_event("startup")
async def startup():
    await init_db()
    asyncio.create_task(database_crawler())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)
