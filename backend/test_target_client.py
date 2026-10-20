import asyncio
from scanner.http_client import SafeHTTPClient

async def main():
    try:
        async with SafeHTTPClient() as client:
            resp = await client.get('https://university-digital-cafteria-frontedd.onrender.com/')
            print(f"Status: {resp.status_code}")
    except Exception as e:
        print(f"Error: {type(e).__name__} - {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
