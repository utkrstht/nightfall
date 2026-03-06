from fastapi import FastAPI, HTTPException
import ipaddress
import asyncio
import random
import sys
from loguru import logger
from cachetools import TTLCache

from models import IPResponse
from database import init_db, get_cached_data, upsert_cache
from engine import fetch_live_data

CRAWLER_DELAY = 1.0 
LRU_CACHE_SIZE = 5000

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
            
            cached = await get_cached_data(target_ip)
            if not cached:
                live_data = await fetch_live_data(target_ip)
                if live_data.success:
                    await upsert_cache(target_ip, live_data.model_dump())
                    logger.info(f"Crawler found {target_ip} ({live_data.prefix})")
                    backoff = CRAWLER_DELAY
                else:
                    backoff = min(backoff * 2, 300)
                    logger.warning(f"Crawler hit empty zone/limit. Backing off to {backoff}s")
            
            await asyncio.sleep(backoff)
        except Exception as e:
            logger.error(f"Crawler loop fault: {e}")
            await asyncio.sleep(10)

@app.get("/ip/{ip_address}", response_model=IPResponse)
async def get_ip_info(ip_address: str):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    if ip_address in hot_cache:
        logger.info(f"LRU HIT for {ip_address}")
        return IPResponse(**hot_cache[ip_address])

    cached = await get_cached_data(ip_address)
    if cached:
        logger.info(f"DB HIT for {ip_address}")
        hot_cache[ip_address] = cached
        return IPResponse(**cached)

    logger.info(f"Cache MISS, pulling live for {ip_address}")
    live_result = await fetch_live_data(ip_address)
    
    if live_result.success:
        data_dict = live_result.model_dump()
        await upsert_cache(ip_address, data_dict)
        hot_cache[ip_address] = data_dict
    
    return live_result

@app.on_event("startup")
async def startup():
    await init_db()
    asyncio.create_task(database_crawler())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)
