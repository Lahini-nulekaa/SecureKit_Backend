# backend/routes/auth_routes.py
from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr
from database import get_database
from securekit import (
    hash_password,
    verify_password,
    create_token,
    verify_totp,
    log_security_event,
    limiter
)

router = APIRouter(tags=["Auth"])

class AuthRequest(BaseModel):
    email: EmailStr
    password: str
    role: Optional[str] = "patient"
    code: Optional[str] = None # For 2FA

class PasswordResetRequest(BaseModel):
    email: EmailStr
    new_password: str
    totp_code: str # Require their 2FA code to reset password

@router.post("/register")
@limiter.limit("5/minute")
async def framework_register(payload: AuthRequest, request: Request):
    db = get_database()
    if db["patients"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed = hash_password(payload.password)
    doc = {
        "email": payload.email,
        "password": hashed, # Framework standardizes on 'password' field
        "role": payload.role.lower(),
        "created_at": str(request.client.host) if request and request.client else "" # Placeholder for logic
    }
    # Note: Added backward compatibility to also set 'hashed_password' if needed
    doc["hashed_password"] = hashed
    
    db["patients"].insert_one(doc)
    log_security_event(f"User registered via framework: {payload.email}")
    return {"message": "Registration successful"}

@router.post("/login")
@limiter.limit("10/minute")
async def framework_login(payload: AuthRequest, request: Request, response: Response):
    db = get_database()
    user = db["patients"].find_one({"email": payload.email})
    
    if not user:
        log_security_event(f"FAILED auth: User not found {payload.email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_hash = user.get("password") or user.get("hashed_password")
    if not verify_password(stored_hash, payload.password):
        log_security_event(f"FAILED auth: Password mismatch {payload.email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    role = user.get("role", "patient")
    
    # 2FA Enforcement
    if user.get("is_2fa_enabled"):
        if not payload.code:
            return {"token": "", "role": role, "requires_2fa": True}
        
        if not verify_totp(user.get("totp_secret"), payload.code):
             raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Issue Framework Token
    token = create_token(
        identity=payload.email,
        role=role,
        expires_in=3600,
        extra_claims={
            "role": role,
            "ip": request.client.host if request.client else None,
            "ua": request.headers.get("user-agent")
        }
    )
    
    # SECURE THE HANDSHAKE
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=3600
    )
    
    log_security_event(f"Successful framework login: {payload.email}")
    return {"token": token, "token_type": "bearer", "role": role, "requires_2fa": False}

@router.post("/reset-password")
@limiter.limit("3/minute")
async def reset_password(payload: PasswordResetRequest, request: Request):
    db = get_database()
    user = db["patients"].find_one({"email": payload.email})
    
    if not user:
        # Prevent email enumeration
        raise HTTPException(status_code=400, detail="Invalid request")
        
    if user.get("is_2fa_enabled"):
        if not verify_totp(user.get("totp_secret"), payload.totp_code):
            log_security_event(f"FAILED password reset: Invalid 2FA {payload.email}")
            raise HTTPException(status_code=401, detail="Invalid 2FA code")
    else:
        # If 2FA is not enabled, we'd normally send an email link.
        # For this system, we require 2FA to be enabled to do self-service reset.
        raise HTTPException(status_code=400, detail="Self-service reset requires 2FA to be active on the account. Please contact admin.")

    hashed = hash_password(payload.new_password)
    db["patients"].update_one(
        {"email": payload.email},
        {"$set": {"password": hashed, "hashed_password": hashed}}
    )
    
    log_security_event(f"Successful password reset for: {payload.email}")
    return {"message": "Password reset successfully"}
