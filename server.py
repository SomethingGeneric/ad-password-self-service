#!/usr/bin/env python3

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from password import PasswordChangeError, change_password

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI()


@app.get("/", response_class=HTMLResponse)
async def read_index() -> FileResponse:
    """Serve the main password change page."""

    return FileResponse(BASE_DIR / "index.html")


@app.get("/passwords.css")
async def serve_css() -> FileResponse:
    return FileResponse(BASE_DIR / "passwords.css")


@app.get("/passwords.js")
async def serve_passwords_js() -> FileResponse:
    return FileResponse(BASE_DIR / "passwords.js")


app.mount("/js", StaticFiles(directory=BASE_DIR / "js"), name="js")


@app.post("/password", response_class=HTMLResponse)
async def change_password_endpoint(
    request: Request,
    username: str = Form(...),
    old_password: str = Form(...),
    new_password: str = Form(...),
    new_password_verify: str = Form(...),
) -> HTMLResponse:
    """Handle password change requests."""

    client_ip: Optional[str] = None
    if request.client:
        client_ip = request.client.host

    apache_user = request.headers.get("x-remote-user", "Unknown")

    try:
        result = change_password(
            username=username,
            old_password=old_password,
            new_password=new_password,
            new_password_verify=new_password_verify,
            log_metadata={
                "apache_user": apache_user,
                "ip": (
                    request.headers.get("x-forwarded-for", client_ip)
                    or client_ip
                    or "Unknown"
                ),
            },
        )
    except PasswordChangeError as exc:
        return HTMLResponse(str(exc), status_code=400)

    status_code = 200 if result.success else 400
    return HTMLResponse(result.message, status_code=status_code)


@app.get("/healthz", response_class=PlainTextResponse)
async def healthcheck() -> str:
    """Simple health check endpoint."""

    return "ok"


def main():
    """Entrypoint compatible with the existing Dockerfile."""

    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    bind = os.environ.get("BIND", "0.0.0.0")

    uvicorn.run("server:app", host=bind, port=port)


if __name__ == "__main__":
    main()
