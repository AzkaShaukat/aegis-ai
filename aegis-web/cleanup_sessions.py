import asyncio, os, pathlib, sys

env_path = pathlib.Path(__file__).parent / ".env.web"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

sys.path.insert(0, str(pathlib.Path(__file__).parent / "backend"))

async def main():
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import text
    async with AsyncSessionLocal() as db:
        r = await db.execute(text(
            "SELECT COUNT(*) FROM chat_sessions "
            "WHERE id NOT IN (SELECT DISTINCT session_id FROM messages)"))
        n = r.scalar()
        print(f"Empty sessions to delete: {n}")
        if n:
            await db.execute(text(
                "DELETE FROM chat_sessions "
                "WHERE id NOT IN (SELECT DISTINCT session_id FROM messages)"))
            await db.commit()
            print(f"Deleted {n} empty sessions")
        else:
            print("Nothing to clean")

asyncio.run(main())
