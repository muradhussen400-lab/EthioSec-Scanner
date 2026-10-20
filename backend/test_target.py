import asyncio
import httpx

async def main():
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get('https://university-digital-cafteria-frontedd.onrender.com/')
            print(f"Status: {resp.status_code}")
    except Exception as e:
        print(f"Error: {type(e).__name__} - {e}")

if __name__ == "__main__":
    asyncio.run(main())
