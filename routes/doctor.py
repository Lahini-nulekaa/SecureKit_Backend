# routes/doctor.py
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, EmailStr
from database import get_database
from securekit import (
    require_role,
    encrypt_text as encrypt_data,
    decrypt_text as decrypt_data,
    limiter,
    log_security_event,
    hash_password
)
from datetime import datetime
import uuid
import time

router = APIRouter(tags=["Doctor"])

class DoctorRegisterSchema(BaseModel):
    full_name: str
    license_id: str
    department: str
    email: EmailStr
    password: str

@router.post("/register")
@limiter.limit("5/minute")
async def register_doctor(doctor: DoctorRegisterSchema, request: Request):
    db = get_database()
    
    # Check if email is already used in patients or doctors
    if db["patients"].find_one({"email": doctor.email}):
        raise HTTPException(status_code=400, detail="Email already registered in system")
    if db["doctors"].find_one({"email": doctor.email}):
        raise HTTPException(status_code=400, detail="Email already registered as an approved doctor")
    if db["doctor_applications"].find_one({"email": doctor.email}):
        raise HTTPException(status_code=400, detail="Application already pending for this email")

    hashed_password = hash_password(doctor.password)

    new_app = {
        "full_name": doctor.full_name,
        "license_id": doctor.license_id,
        "department": doctor.department,
        "email": doctor.email,
        "password": hashed_password,
        "status": "PENDING_APPROVAL",
        "created_at": time.time()
    }

    db["doctor_applications"].insert_one(new_app)
    log_security_event(f"New doctor application submitted: {doctor.email}")
    return {"message": "Application submitted successfully. Pending admin approval."}

@router.api_route("/me", methods=["GET", "PUT"])
async def get_doctor_me(request: Request, payload: dict = Depends(require_role(["Doctor"]))):
    email = payload.get("sub")
    db = get_database()
    
    if request.method == "GET":
        doc = db["patients"].find_one({"email": email, "role": "doctor"})
        if not doc:
            doc = db["doctors"].find_one({"email": email})
        if not doc:
            raise HTTPException(status_code=404, detail="Doctor profile not found")
        
        return {
            "email": doc.get("email"),
            "full_name": doc.get("full_name") or doc.get("name") or doc.get("doctor_name"),
            "license_id": doc.get("license_id"),
            "department": doc.get("department") or doc.get("specialty") or doc.get("specialization")
        }
        
    # PUT method
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    updates = {}
    if "full_name" in body: updates["full_name"] = body["full_name"]
    if "license_id" in body: updates["license_id"] = body["license_id"]
    if "department" in body: updates["department"] = body["department"]
    
    if updates:
        db["patients"].update_one({"email": email, "role": "doctor"}, {"$set": updates})
        db["doctors"].update_one({"email": email}, {"$set": updates})
        log_security_event(f"Doctor profile updated: {email}")
        
    doc = db["patients"].find_one({"email": email, "role": "doctor"}) or db["doctors"].find_one({"email": email}) or {}
    
    return {
        "message": "Profile updated successfully",
        "email": doc.get("email"),
        "full_name": doc.get("full_name") or doc.get("name") or doc.get("doctor_name"),
        "license_id": doc.get("license_id"),
        "department": doc.get("department") or doc.get("specialty") or doc.get("specialization")
    }

class DiagnosisSchema(BaseModel):
    patient_id: str
    diagnosis_details: str
    prescription: str

# 0. POST /login - Unified secure login for Doctors (Redirected)
@router.post("/login")
@limiter.limit("10/minute")
async def doctor_login(request: Request, response: Response):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/auth/login", status_code=307)

# 1. POST /diagnosis - Protected by RBAC, Encrypts medical records (Layer 4)
@router.post("/diagnosis")
async def create_diagnosis(diagnosis: DiagnosisSchema, payload: dict = Depends(require_role(["Doctor"]))):
    db = get_database()
    
    patient = db["patients"].find_one({"email": diagnosis.patient_id}) or db["patients"].find_one({"_id": diagnosis.patient_id})
    if not patient:
         raise HTTPException(status_code=404, detail="Patient not found")

    cipher_diagnosis = encrypt_data(diagnosis.diagnosis_details)
    cipher_prescription = encrypt_data(diagnosis.prescription)

    new_record = {
        "record_id": str(uuid.uuid4()),
        "patient_id": diagnosis.patient_id,
        "doctor_email": payload.get("sub"),
        "diagnosis_details": cipher_diagnosis, 
        "prescription": cipher_prescription, 
        "created_at": datetime.utcnow().isoformat()
    }

    res = db["medical_records"].insert_one(new_record)
    return {"message": "Diagnosis recorded securely", "id": str(res.inserted_id)}

# 2. GET /patient-records/{patient_id} - Protected by RBAC, Decrypts clinical records
@router.get("/patient-records/{patient_id}")
async def get_patient_records(patient_id: str, payload: dict = Depends(require_role(["Doctor"]))):
    db = get_database()
    records = list(db["medical_records"].find({"patient_id": patient_id}))
    
    if not records:
        raise HTTPException(status_code=404, detail="No clinical records found for this patient")

    decrypted_records = []
    for r in records:
        r["diagnosis_details"] = decrypt_data(r.get("diagnosis_details"))
        r["prescription"] = decrypt_data(r.get("prescription"))
        r.pop("_id", None)
        decrypted_records.append(r)

    return {"patient_id": patient_id, "records": decrypted_records}

@router.get("/appointments")
async def get_doctor_appointments(payload: dict = Depends(require_role(["Doctor"]))):
    db = get_database()
    email = payload.get("sub")
    cursor = db["appointments"].find({"doctor_email": email}, {"_id": 0})
    return {"count": 0, "data": list(cursor)}

class DecisionSchema(BaseModel):
    status: str
    rejection_reason: str = None

@router.put("/appointments/{appointment_id}/decision")
async def decision_appointment(appointment_id: str, dec: DecisionSchema, payload: dict = Depends(require_role(["Doctor"]))):
    db = get_database()
    email = payload.get("sub")
    updates = {"status": dec.status}
    if dec.rejection_reason:
        updates["rejection_reason"] = dec.rejection_reason

    result = db["appointments"].update_one(
        {"appointment_id": appointment_id, "doctor_email": email},
        {"$set": updates}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found or unaltered")
    return {"message": f"Appointment marked as {dec.status}"}

# --- NEW: Patient Management for Doctors ---

@router.get("/patients")
async def get_doctor_assigned_patients(payload: dict = Depends(require_role(["Doctor"]))):
    """Retrieve all patients assigned to this specific doctor."""
    db = get_database()
    email = payload.get("sub")
    
    # Find patients assigned to this doctor
    patients_cursor = db["patients"].find({"assigned_doctor_email": email}, {"password": 0, "_id": 0})
    patients_list = list(patients_cursor)
    
    return {"count": len(patients_list), "data": patients_list}

@router.get("/patients/{email}")
async def get_patient_profile_for_doctor(email: str, payload: dict = Depends(require_role(["Doctor"]))):
    """Retrieve detailed profile for an assigned patient."""
    db = get_database()
    doctor_email = payload.get("sub")
    
    patient = db["patients"].find_one({"email": email, "assigned_doctor_email": doctor_email}, {"password": 0, "_id": 0})
    if not patient:
        # Check if they have an appointment together
        appt = db["appointments"].find_one({"patient_email": email, "doctor_email": doctor_email})
        if not appt:
            raise HTTPException(status_code=403, detail="Access denied: Patient not assigned to you")
        
        patient = db["patients"].find_one({"email": email}, {"password": 0, "_id": 0})
        if not patient:
            raise HTTPException(status_code=404, detail="Patient entity not found")

    return patient

class MedicalHistoryUpdate(BaseModel):
    medical_history: str

@router.put("/patients/{email}/medical-history")
async def update_patient_medical_history(email: str, data: MedicalHistoryUpdate, payload: dict = Depends(require_role(["Doctor"]))):
    """Update medical history for an assigned patient."""
    db = get_database()
    doctor_email = payload.get("sub")
    
    # Security check: Ensure assignment
    patient = db["patients"].find_one({"email": email, "assigned_doctor_email": doctor_email})
    if not patient:
        appt = db["appointments"].find_one({"patient_email": email, "doctor_email": doctor_email})
        if not appt:
            raise HTTPException(status_code=403, detail="Access denied: Cannot modify non-assigned patient")

    db["patients"].update_one(
        {"email": email},
        {"$set": {"medical_history": data.medical_history}}
    )
    
    log_security_event(f"Doctor {doctor_email} updated medical history for patient {email}")
    return {"message": "Medical history updated successfully"}