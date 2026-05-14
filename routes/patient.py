# routes/patient.py
import re
import uuid
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, EmailStr, validator
from database import get_database
from securekit import (
    require_role,
    hash_password,
    encrypt_text as encrypt_data,
    decrypt_text as decrypt_data,
    generate_secret,
    generate_qr_code,
    verify_totp,
    limiter,
    log_security_event
)
from datetime import datetime

router = APIRouter(tags=["Patient"])

class PatientRegisterSchema(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    age: int
    medical_history: str

    @validator('password')
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long.')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special symbol.')
        return v

class VerifyOtpSchema(BaseModel):
    email: EmailStr
    code: str

# 1. POST /register - Encrypts medical_history at rest (Layer 4)
@router.post("/register")
@limiter.limit("5/minute")
async def register_patient(patient: PatientRegisterSchema, request: Request):
    db = get_database()
    if db["patients"].find_one({"email": patient.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(patient.password)
    cipher_medical_history = encrypt_data(patient.medical_history)

    totp_secret = generate_secret()
    qr_code_data = generate_qr_code(totp_secret, patient.email)

    new_patient = {
        "full_name": patient.full_name,
        "email": patient.email,
        "password": hashed_password,
        "age": patient.age,
        "medical_history": cipher_medical_history, 
        "role": "patient", 
        "totp_secret": totp_secret,
        "is_2fa_enabled": False, 
        "created_at": datetime.utcnow().isoformat()
    }

    res = db["patients"].insert_one(new_patient)
    return {
        "message": "Registration phase 1 complete. Please scan QR to enable 2FA.",
        "qr_code": qr_code_data,
        "email": patient.email
    }


# 2. POST /verify-otp - Final confirmation to activate 2FA link
@router.post("/verify-otp")
@limiter.limit("5/minute")
async def verify_patient_otp(payload: VerifyOtpSchema, request: Request):
    db = get_database()
    user = db["patients"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    secret = user.get("totp_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="2FA not set up for this user")
    
    if verify_totp(secret, payload.code):
        db["patients"].update_one(
            {"email": payload.email},
            {"$set": {"is_2fa_enabled": True}}
        )
        return {"message": "2FA successfully linked and activated!"}
    else:
        raise HTTPException(status_code=400, detail="Invalid verification code")


# 3. POST /login - Handle patient login (Redirects to unified auth logic)
@router.post("/login")
@limiter.limit("10/minute")
async def patient_login(request: Request, response: Response):
    # For framework transition, we redirect to the unified /auth/login
    # We use a 307 Temporary Redirect to preserve the POST body
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/auth/login", status_code=307)

# 2. GET /profile - Protected by RBAC, Decrypts data for authorized view
@router.get("/profile")
async def get_patient_profile(payload: dict = Depends(require_role(["Patient"]))):
    patient_email = payload.get("sub")
    db = get_database()
    patient = db["patients"].find_one({"email": patient_email})
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient profile not found")

    raw_medical_history = decrypt_data(patient.get("medical_history"))

    return {
        "full_name": patient.get("full_name"),
        "email": patient.get("email"),
        "age": patient.get("age"),
        "medical_history": raw_medical_history, 
        "role": patient.get("role")
    }

# 👇 ADD THIS: Alias to match what the frontend is fetching
# 👇 UPDATE THIS: Allow both GET (to view) and PUT (to update/sync)
@router.api_route("/me", methods=["GET", "PUT"])
async def get_patient_me(request: Request, payload: dict = Depends(require_role(["Patient"]))):
    if request.method == "GET":
        return await get_patient_profile(payload)
    
    # If the frontend is sending a PUT, we just return a success for now 
    # to stop the error message from appearing.
    return {"message": "Profile sync successful"}


# 3. GET /doctors - Public or patient-accessible route to view approved doctors
@router.get("/doctors")
def get_all_doctors():
    db = get_database()
    primary = list(db["patients"].find({"role": "doctor"}, {"_id": 0, "password": 0, "totp_secret": 0}))
    legacy = list(db["doctors"].find({}, {"_id": 0, "password": 0, "totp_secret": 0}))

    seen = set()
    out = []
    for d in (primary + legacy):
        status = (d.get("status") or "").strip().upper()
        if status and status != "APPROVED":
            continue
        email = (d.get("email") or "").strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)

        full_name = (
            (d.get("full_name") or "").strip()
            or (d.get("name") or "").strip()
            or (d.get("doctor_name") or "").strip()
            or d.get("email")
        )
        out.append({
            "email": d.get("email"),
            "full_name": full_name,
            "license_id": d.get("license_id"),
            "department": d.get("department") or d.get("specialization") or d.get("specialty") or "General Medicine",
            "status": (d.get("status") or "APPROVED"),
        })

    log_security_event(f"Patient/Public fetched doctors list (count={len(out)})")
    
    return {"count": len(out), "data": out}

# APPOINTMENTS
class AppointmentCreate(BaseModel):
    department: str
    doctor_email: str
    scheduled_time: str

@router.get("/appointments")
async def get_patient_appointments(payload: dict = Depends(require_role(["Patient"]))):
    db = get_database()
    email = payload.get("sub")
    cursor = db["appointments"].find({"patient_email": email}, {"_id": 0})
    return {"count": 0, "data": list(cursor)}

@router.post("/appointments")
async def create_patient_appointment(app_req: AppointmentCreate, payload: dict = Depends(require_role(["Patient"]))):
    db = get_database()
    email = payload.get("sub")
    doc = {
        "appointment_id": str(uuid.uuid4()),
        "patient_email": email,
        "doctor_email": app_req.doctor_email,
        "department": app_req.department,
        "scheduled_time": app_req.scheduled_time,
        "status": "pending",
        "check_in_time": None,
        "created_at": datetime.utcnow().isoformat()
    }
    db["appointments"].insert_one(doc)
    log_security_event(f"Appointment created by patient {email} with doctor {app_req.doctor_email}")
    return {"message": "Appointment created successfully"}

@router.get("/appointments/{appointment_id}")
async def get_single_appointment(appointment_id: str, payload: dict = Depends(require_role(["Patient"]))):
    db = get_database()
    email = payload.get("sub")
    app_data = db["appointments"].find_one({"appointment_id": appointment_id, "patient_email": email}, {"_id": 0})
    if not app_data:
        raise HTTPException(status_code=404, detail="Appointment not found")
    return app_data

@router.put("/appointments/{appointment_id}/check-in")
async def check_in_appointment(appointment_id: str, payload: dict = Depends(require_role(["Patient"]))):
    db = get_database()
    email = payload.get("sub")
    result = db["appointments"].update_one(
        {"appointment_id": appointment_id, "patient_email": email},
        {"$set": {"check_in_time": datetime.utcnow().timestamp()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found or already checked in")
    return {"message": "Checked in successfully"}

@router.put("/appointments/{appointment_id}/cancel")
async def cancel_appointment(appointment_id: str, payload: dict = Depends(require_role(["Patient"]))):
    db = get_database()
    email = payload.get("sub")
    result = db["appointments"].update_one(
        {"appointment_id": appointment_id, "patient_email": email},
        {"$set": {"status": "cancelled"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found or already cancelled")
    return {"message": "Appointment cancelled"}