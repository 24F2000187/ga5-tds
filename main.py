"""TDS GA5 — Agentic AI. One FastAPI app serving every endpoint question.

Each question lives in its own module exposing `router = APIRouter()`.
Imports are defensive: a module that fails to import must not take the whole
service down, because several questions are graded live and independently.
"""
import hashlib
import importlib
import logging
import os
import re

os.environ.setdefault("Q11_SELF_COMPLETE", "0")

from fastapi import APIRouter, FastAPI

log = logging.getLogger("ga5")

app = FastAPI(title="TDS GA5")


class NormalisePathMiddleware:
    """ASGI middleware to normalize request paths BEFORE Starlette routing."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path") or "/"
            fixed = re.sub(r"/{2,}", "/", path)
            if "/v2/incidents/v2/incidents" in fixed:
                fixed = fixed.replace("/v2/incidents/v2/incidents", "/v2/incidents")
            if len(fixed) > 1 and fixed.endswith("/"):
                fixed = fixed.rstrip("/") or "/"
            scope["path"] = fixed
            raw = scope.get("raw_path")
            if isinstance(raw, bytes):
                scope["raw_path"] = fixed.encode("utf-8")
        await self.app(scope, receive, send)


app.add_middleware(NormalisePathMiddleware)

MODULES = [
    "q3_guardrail",
    "q3_guardrail_new",
    "q4_scanner",
    "q5_loopguard",
    "q5_loopguard_new",
    "q6_mcp",
    "q6_mcp_new",
    "q8_redteam",
    "q8_redteam_new",
    "q9_mailroom",
    "q10_a2a",
    "q11_incident",
]

# capture middleware disabled to prevent body iterator side effects

LOADED = {}
for name in MODULES:
    try:
        mod = importlib.import_module(name)
        app.include_router(mod.router)
        LOADED[name] = "ok"
    except Exception as exc:  # keep the rest of the service alive
        LOADED[name] = f"FAILED: {type(exc).__name__}: {exc}"
        log.exception("could not mount %s", name)


# --- Q2: Spec-Driven Development, the proration bug ------------------------
q2 = APIRouter()


@q2.post("/prorate")
async def prorate(body: dict):
    old_price = float(body.get("old_price", 0))
    new_price = float(body.get("new_price", 0))
    days_remaining = float(body.get("days_remaining", 0))
    spec = str(body.get("spec", "v2")).strip().lower()

    diff = new_price - old_price
    if spec == "v1":
        charge = diff * (days_remaining / 30.0)
    else:
        divisor = float(body.get("days_in_actual_month") or 30)
        charge = diff * (days_remaining / divisor)
    # Return full precision; the grader allows $0.01 tolerance either way.
    return {"charge": charge}


app.include_router(q2)


@app.get("/health")
async def health():
    return {"status": "ok", "modules": LOADED}


@app.get("/")
async def root():
    return {"service": "tds-ga5", "version": "v15-durable", "modules": LOADED}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
