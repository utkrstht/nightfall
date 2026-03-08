import aiosqlite
import json
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

DB_PATH = "db/ip_geolocation.db"
_db_pool: Optional[aiosqlite.Connection] = None

async def init_db():
    global _db_pool
    if _db_pool is None:
        _db_pool = await aiosqlite.connect(DB_PATH)
        _db_pool.row_factory = aiosqlite.Row
        
    await _db_pool.execute('''CREATE TABLE IF NOT EXISTS prefix_cache 
                                  (prefix TEXT PRIMARY KEY, 
                                   data TEXT, 
                                   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    await _db_pool.execute('''CREATE TABLE IF NOT EXISTS ip_prefix_map 
                                  (ip TEXT PRIMARY KEY, 
                                   prefix TEXT,
                                   FOREIGN KEY(prefix) REFERENCES prefix_cache(prefix))''')
    await _db_pool.execute('CREATE INDEX IF NOT EXISTS idx_prefix_updated ON prefix_cache(updated_at)')
    await _db_pool.commit()
    logger.info("Database initialized successfully.")

async def close_db():
    global _db_pool
    if _db_pool:
        await _db_pool.close()
        _db_pool = None

async def get_cached_data_by_ip(ip: str) -> Optional[dict]:
    if _db_pool is None:
        await init_db()
    
    query = """
    SELECT pc.data 
    FROM ip_prefix_map ipm
    JOIN prefix_cache pc ON ipm.prefix = pc.prefix
    WHERE ipm.ip = ?
    """
    async with _db_pool.execute(query, (ip,)) as cursor:
        row = await cursor.fetchone()
        return json.loads(row['data']) if row else None

async def get_cached_data_by_prefix(prefix: str) -> Optional[dict]:
    if _db_pool is None:
        await init_db()
    
    async with _db_pool.execute("SELECT data FROM prefix_cache WHERE prefix = ?", (prefix,)) as cursor:
        row = await cursor.fetchone()
        return json.loads(row['data']) if row else None

async def upsert_prefix_cache(ip: str, prefix: str, data: dict):
    if _db_pool is None:
        await init_db()
        
    await _db_pool.execute("INSERT OR REPLACE INTO prefix_cache (prefix, data, updated_at) VALUES (?, ?, ?)",
                         (prefix, json.dumps(data), datetime.now(timezone.utc).isoformat()))
    
    asn = data.get("connection", {}).get("asn")
    if asn:
        await _db_pool.execute('''CREATE TABLE IF NOT EXISTS asn_prefix_map 
                                  (asn INTEGER, 
                                   prefix TEXT, 
                                   PRIMARY KEY(asn, prefix))''')
        await _db_pool.execute("INSERT OR IGNORE INTO asn_prefix_map (asn, prefix) VALUES (?, ?)", (asn, prefix))

    await _db_pool.execute("INSERT OR REPLACE INTO ip_prefix_map (ip, prefix) VALUES (?, ?)", (ip, prefix))
    await _db_pool.commit()

async def get_prefixes_by_asn(asn: int) -> list:
    if _db_pool is None:
        await init_db()
    
    async with _db_pool.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='asn_prefix_map'") as cursor:
        if not await cursor.fetchone():
            return []

    async with _db_pool.execute("SELECT prefix FROM asn_prefix_map WHERE asn = ?", (asn,)) as cursor:
        rows = await cursor.fetchall()
        return [row['prefix'] for row in rows]
