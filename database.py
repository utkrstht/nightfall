import aiosqlite
import json
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

DB_PATH = "db/ip_geolocation.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''CREATE TABLE IF NOT EXISTS ip_cache 
                            (ip TEXT PRIMARY KEY, 
                             data TEXT, 
                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        await db.execute('CREATE INDEX IF NOT EXISTS idx_updated ON ip_cache(updated_at)')
        await db.commit()
    logger.info("Database initialized successfully.")

async def get_cached_data(ip: str) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT data FROM ip_cache WHERE ip=?", (ip,)) as cursor:
            row = await cursor.fetchone()
            return json.loads(row['data']) if row else None

async def upsert_cache(ip: str, data: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO ip_cache (ip, data, updated_at) VALUES (?, ?, ?)",
                         (ip, json.dumps(data), datetime.now(timezone.utc).isoformat()))
        await db.commit()
