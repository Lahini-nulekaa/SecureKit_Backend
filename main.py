# backend/main.py
import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from securekit import log_security_event, limiter
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from pymongo.errors import PyMongoError

# 👇 NEW: Framework Initialization
from securekit.core import boot_securekit
from securekit.middleware.geo_blocker import GeoShield

# Load env vars from .env (project root or backend/.env) for local dev.
_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _BACKEND_DIR.parent
load_dotenv(_PROJECT_ROOT / ".env", override=False)
load_dotenv(_BACKEND_DIR / ".env", override=False)

# Initialize SecureKit Framework (Inversion of Control) MUST BE BEFORE ROUTE IMPORTS
securekit = boot_securekit({
    "secret_key": os.getenv("SECRET_KEY"),
    "encryption_key": os.getenv("DATA_ENCRYPTION_KEY"),
    "roles": ["admin", "patient", "doctor", "guest"],
    "blocked_countries": ["XX"], # Example
    "trusted_ips": ["127.0.0.1"]
})

# 👇 NEW: Import the database connection to run the check
from database import get_database
# 👇 NEW: Import the patient and admin routers (package-relative)
from routes import patient
from routes import admin
from routes import doctor
from routes import auth_routes

# Fail-safe: Detect if we are in production
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("CRITICAL ERROR: SECRET_KEY environment variable is not set.")

# Disable automatic documentation in production
app_kwargs = {}
if ENVIRONMENT == "production":
    app_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}

app = FastAPI(**app_kwargs)

# 👇 NEW: Security Headers Middleware
# @app.middleware("http")
# async def add_security_headers(request: Request, call_next):
#     response = await call_next(request)
#     # HSTS - Forces browsers to use HTTPS
#     response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
#     # Prevents Clickjacking
#     response.headers["X-Frame-Options"] = "DENY"
#     # Prevents MIME-sniffing attacks
#     response.headers["X-Content-Type-Options"] = "nosniff"
#     # Enables XSS filtering in browsers
#     response.headers["X-XSS-Protection"] = "1; mode=block"
    # Basic Content Security Policy
#     response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; img-src 'self' data: https:;"
#     return response

# 👇 NEW: Connect the router to the app

app.include_router(patient.router, prefix="/patient", tags=["Patients"])
app.include_router(admin.router, prefix="/admin", tags=["Admin Dashboard"])
app.include_router(doctor.router, prefix="/doctor", tags=["Doctors"])
app.include_router(auth_routes.router, prefix="/auth", tags=["Auth"])

# Strict CORS Configuration
# Simplified and safer CORS setup
frontend_url_env = os.getenv("FRONTEND_URL")
if not frontend_url_env:
    raise RuntimeError("CRITICAL ERROR: FRONTEND_URL environment variable is not set.")
ALLOWED_ORIGINS = frontend_url_env.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS], # .strip() removes accidental spaces
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 👇 NEW: Geo-Blocking Middleware (GeoShield)
app.add_middleware(GeoShield)
# 👇 NEW: Configure Rate Limiting
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    client_ip = request.client.host if request.client else "Unknown"
    log_security_event(f"SECURITY ALERT: Rate limit exceeded for IP {client_ip} on {request.url.path}")
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. For security reasons, your access is temporarily restricted."}
    )

# 👇 NEW: Verify DB connection on startup
@app.on_event("startup")
def startup_db_client():
    get_database()
    log_security_event("Database connection initialized.")


# 👇 NEW: Handle database crashes cleanly
@app.exception_handler(PyMongoError)
async def database_exception_handler(request: Request, exc: PyMongoError):
    log_security_event(f"Database error on {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "A critical database error occurred. Please try again later."})

# Global exception handler to return JSON on server errors (helps frontend parse errors)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log_security_event(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"detail": str(exc)})

@app.api_route("/", methods=["GET", "HEAD"])
def read_root(request: Request):
    log_security_event(f"Someone accessed the root page via {request.method}.")
    return {"message": "SecureKit Healthcare System is Running!"}

@app.get("/login")
def login_simulation():
    log_security_event("Login Attempt Detected!")
    return {"status": "Login page ready"}