import uvicorn
from fastapi import FastAPI, Request, Response, Header
from fastapi.responses import HTMLResponse, JSONResponse
import html

app = FastAPI()

# Secure headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <body>
            <h1>Secure App</h1>
            <a href="/login">Login Page</a>
            <a href="/search">Search Page</a>
            <a href="/api/users/1">User 1</a>
            <a href="/api/users/2">User 2</a>
            <a href="/api/me">My Profile</a>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
        <body>
            <h1>Login</h1>
            <form action="/api/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
        </body>
    </html>
    """

@app.get("/search", response_class=HTMLResponse)
async def search(q: str = ""):
    safe_q = html.escape(q)
    return f"""
    <html>
        <body>
            <h1>Search</h1>
            <form action="/search" method="GET">
                <input type="text" name="q" value="{safe_q}"/>
                <input type="submit" value="Search" />
            </form>
            <p>You searched for: {safe_q}</p>
        </body>
    </html>
    """

@app.post("/api/login", response_class=HTMLResponse)
async def api_login_post(request: Request):
    form = await request.form()
    user = form.get("username", "")
    # Secure: No SQLi vulnerability
    return HTMLResponse("Login failed", status_code=200)

@app.get("/api/login", response_class=HTMLResponse)
async def api_login_get(username: str = ""):
    # Secure: No SQLi vulnerability
    return HTMLResponse("Login failed", status_code=200)

@app.get("/api/me")
async def api_me(authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return {"user": authorization}

@app.get("/api/users/{user_id}")
async def api_users(user_id: str, authorization: str = Header(None)):
    if not authorization:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    
    # Secure: Enforce IDOR check
    # Assume "Bearer token1" is User 1, "Bearer token2" is User 2
    if authorization == "Bearer token1" and user_id != "1":
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})
    if authorization == "Bearer token2" and user_id != "2":
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})
        
    return {"id": user_id, "data": f"Secret data for {user_id}"}

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=3001, log_level="warning")
