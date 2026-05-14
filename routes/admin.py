# routes/admin.py
from fastapi import APIRouter, Header, HTTPException, Request
from database import get_database
from database import get_database
from securekit import (
    log_security_event,
    create_token,
    verify_token,
    decrypt_text,
    limiter
)
import os
import time
import datetime
import datetime

router = APIRouter()

ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not ADMIN_API_KEY or not ADMIN_PASSWORD:
    raise RuntimeError("CRITICAL ERROR: ADMIN_API_KEY or ADMIN_PASSWORD environment variable is not set.")


def _require_admin_from_bearer(authorization: str | None, request: Request) -> None:
    if not authorization:
        raise HTTPException(status_code=401, detail='Missing admin Authorization header')
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise HTTPException(status_code=401, detail='Invalid Authorization header')
    client_ip = request.client.host if request and request.client else None
    user_agent = request.headers.get('user-agent') if request else None
    payload = verify_token(parts[1], expected_ip=client_ip, expected_ua=user_agent)
    if not payload:
        raise HTTPException(status_code=401, detail='Invalid or expired token')
    if payload.get('role') != 'admin':
        raise HTTPException(status_code=403, detail='Admin access required')

def require_admin(authorization: str = Header(None), x_api_key: str = Header(None), request: Request = None):
    """Authorize admin requests."""
    # Legacy support
    if x_api_key is not None:
        if x_api_key != ADMIN_API_KEY:
            raise HTTPException(status_code=403, detail='Invalid admin API key')
        return

    # Preferred bearer token
    _require_admin_from_bearer(authorization, request)
    return


def _normalize_email(value: str | None) -> str:
	return (value or "").strip().lower()


def _normalize_scheduled_time(value: str | None) -> str:
    """Normalize scheduled time string for equality comparisons."""
    text = (value or '').strip()
    if not text:
        return ''
    try:
        dt = datetime.datetime.fromisoformat(text)
        dt = dt.replace(second=0, microsecond=0)
        return dt.isoformat(timespec='minutes')
    except Exception:
        # fallback: best-effort minute precision
        return text[:16]


@router.post('/login')
@limiter.limit("5/minute")
def admin_login(payload: dict, request: Request):
    """Admin login using a shared admin password."""
    password = payload.get('password')
    if not password:
        raise HTTPException(status_code=400, detail='Password required')
    if password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail='Invalid admin password')

    # Role-scoped token so we can distinguish from doctor/patient tokens.
    client_ip = request.client.host if request and request.client else None
    user_agent = request.headers.get('user-agent') if request else None
    extra_claims: dict = {'role': 'admin'}
    if client_ip:
        extra_claims['ip'] = client_ip
    if user_agent:
        extra_claims['ua'] = user_agent[:256]
    token = create_token('admin', role='admin', expires_in=60 * 60 * 24, extra_claims=extra_claims)
    log_security_event('Admin login')
    return {'token': token}

# 1. Endpoint to View All Patients
@router.get("/patients")
def get_all_patients(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    require_admin(authorization, x_api_key, request)
    db = get_database()
    patients = list(db["patients"].find({}, {"_id": 0, "password": 0, "totp_secret": 0}))
    patients = [p for p in patients if (p.get('role') or 'patient') == 'patient']
    for p in patients:
        if 'medical_history' in p:
            try:
                p['medical_history'] = decrypt_text(p.get('medical_history'))
            except Exception:
                p['medical_history'] = ''
    log_security_event(f"Admin fetched patients list (count={len(patients)})")
    return {"count": len(patients), "data": patients}

# 2. Endpoint to View Security Logs
@router.get("/system-logs")
def get_security_logs(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    require_admin(authorization, x_api_key, request)
    log_security_event("Admin fetched system logs")
    from pathlib import Path
    try:
        log_path = Path(__file__).resolve().parent.parent / "security_audit.log"
        if not log_path.exists():
            # Fallback to current working directory if not found in parent
            log_path = Path("security_audit.log")

        with open(log_path, "r", encoding="utf-8") as log_file:
            logs = log_file.readlines()
        
        # Return newest logs first
        return {"recent_logs": [line.strip() for line in reversed(logs[-20:])]}
    except FileNotFoundError:
        return {"error": "No logs found yet."}


@router.get("/doctors")
def get_all_doctors(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Return all doctor accounts."""
    require_admin(authorization, x_api_key, request)
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

    log_security_event(f"Admin fetched doctors list (count={len(out)})")
    return {"count": len(out), "data": out}


@router.get('/doctors/pending')
def get_pending_doctor_applications(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Return pending doctor applications."""
    require_admin(authorization, x_api_key, request)
    db = get_database()
    pending = list(db['doctor_applications'].find({'status': 'PENDING_APPROVAL'}, {'_id': 0, 'password': 0, 'totp_secret': 0}))
    legacy_pending = list(db['doctors'].find({'status': 'PENDING_APPROVAL'}, {'_id': 0, 'password': 0, 'totp_secret': 0}))
    out = []
    for d in (pending + legacy_pending):
        out.append({
            'email': d.get('email'),
            'full_name': d.get('full_name') or d.get('name') or d.get('doctor_name') or d.get('email'),
            'license_id': d.get('license_id'),
            'department': d.get('department') or d.get('specialization') or d.get('specialty') or 'General Medicine',
            'status': d.get('status') or 'PENDING_APPROVAL',
            'created_at': d.get('created_at'),
        })

    log_security_event(f"Admin fetched pending doctor applications (count={len(out)})")
    return {'count': len(out), 'data': out}


@router.put('/doctors/{doctor_email}/decision')
def decide_doctor_application(doctor_email: str, payload: dict, request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Approve or reject a doctor application."""
    require_admin(authorization, x_api_key, request)

    decision = (payload.get('decision') or '').strip().lower()
    reason = (payload.get('reason') or '').strip()
    if decision not in ('approve', 'reject'):
        raise HTTPException(status_code=400, detail='decision must be approve or reject')

    db = get_database()
    app = db['doctor_applications'].find_one({'email': doctor_email})
    legacy_app = None if app else db['doctors'].find_one({'email': doctor_email, 'status': 'PENDING_APPROVAL'})
    if not app and not legacy_app:
        raise HTTPException(status_code=404, detail='Doctor application not found')

    record = app or legacy_app

    if decision == 'approve':
        approved = dict(record)
        approved['status'] = 'APPROVED'
        approved['reviewed_at'] = time.time()
        approved['review_reason'] = None
        existing = db['doctors'].find_one({'email': doctor_email})
        if existing:
            db['doctors'].update_one({'email': doctor_email}, {'$set': {'status': 'APPROVED', 'reviewed_at': approved['reviewed_at'], 'review_reason': None}})
        else:
            db['doctors'].insert_one(approved)
        if app:
            db['doctor_applications'].delete_one({'email': doctor_email})
        else:
            db['doctors'].update_one({'email': doctor_email}, {'$set': {'status': 'APPROVED', 'reviewed_at': time.time(), 'review_reason': None}})

        # Ensure doctor is added to 'patients' collection for unified login
        patient_record = db['patients'].find_one({'email': doctor_email})
        if not patient_record:
            new_patient = dict(approved)
            new_patient.pop('_id', None)
            new_patient['role'] = 'doctor'
            db['patients'].insert_one(new_patient)
        else:
            db['patients'].update_one({'email': doctor_email}, {'$set': {'role': 'doctor', 'status': 'APPROVED'}})

        log_security_event(f"Admin approved doctor application: {doctor_email}")
        return {'email': doctor_email, 'status': 'APPROVED'}

    if app:
        db['doctor_applications'].update_one(
            {'email': doctor_email},
            {'$set': {'status': 'REJECTED', 'reviewed_at': time.time(), 'review_reason': reason}}
        )
    else:
        db['doctors'].update_one(
            {'email': doctor_email},
            {'$set': {'status': 'REJECTED', 'reviewed_at': time.time(), 'review_reason': reason}}
        )

    log_security_event(f"Admin rejected doctor application: {doctor_email}")
    return {'email': doctor_email, 'status': 'REJECTED'}


@router.put("/patients/{patient_email}/assigned-doctor")
def set_patient_assigned_doctor(patient_email: str, payload: dict, request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Assign (or unassign) a patient to a doctor."""
    require_admin(authorization, x_api_key, request)

    doctor_email = payload.get("doctor_email")
    doctor_email_norm = _normalize_email(doctor_email) if doctor_email is not None else ""
    patient_email_norm = _normalize_email(patient_email)
    if not patient_email_norm:
        raise HTTPException(status_code=400, detail="Invalid patient email")

    db = get_database()
    patient = db["patients"].find_one({"email": patient_email})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    if patient.get("role") == "doctor":
        raise HTTPException(status_code=400, detail="Target email belongs to a doctor account")

    if doctor_email is not None:
        doctor = db["patients"].find_one({"email": doctor_email, "role": "doctor"})
        if not doctor:
            doctor = db["doctors"].find_one({"email": doctor_email})
        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")

    update_value = doctor_email_norm if doctor_email is not None else None
    res = db["patients"].update_one({"email": patient_email}, {"$set": {"assigned_doctor_email": update_value}})
    matched = getattr(res, "matched_count", 0)
    if matched == 0:
        raise HTTPException(status_code=404, detail="Patient not found")

    log_security_event(f"Admin set assigned_doctor_email for {patient_email_norm} -> {doctor_email_norm or 'None'}")
    return {"patient_email": patient_email_norm, "assigned_doctor_email": update_value}


@router.get('/appointments')
def admin_list_appointments(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Admin review: list all appointments."""
    require_admin(authorization, x_api_key, request)
    db = get_database()
    rows = list(db['appointments'].find({}, {'_id': 0}))
    
    # Robust sort: Handle cases where created_at is missing, None, or a string
    def _sort_key(r):
        val = r.get('created_at')
        if val is None: return 0
        try:
            return float(val)
        except (ValueError, TypeError):
            return 0

    rows.sort(key=_sort_key, reverse=True)
    return {'count': len(rows), 'data': rows}


@router.put('/appointments/{appointment_id}/approve')
def admin_approve_appointment(appointment_id: str, payload: dict, request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Approve a pending appointment and assign/override the doctor."""
    require_admin(authorization, x_api_key, request)

    override_doctor_email = payload.get('doctor_email')
    if override_doctor_email is not None:
        override_doctor_email = str(override_doctor_email).strip()

    db = get_database()
    appt = db['appointments'].find_one({'appointment_id': appointment_id})
    if not appt:
        raise HTTPException(status_code=404, detail='Appointment not found')

    if (appt.get('status') or 'pending') != 'pending':
        raise HTTPException(status_code=400, detail='Only pending appointments can be approved')

    final_doctor_email = override_doctor_email or appt.get('doctor_email')
    if not final_doctor_email:
        raise HTTPException(status_code=400, detail='doctor_email is required')

    slot = _normalize_scheduled_time(appt.get('scheduled_time'))
    if not slot:
        raise HTTPException(status_code=400, detail='scheduled_time is required')

    active_statuses = {'approved', 'accepted', 'checked_in'}
    other_rows = list(db['appointments'].find({'doctor_email': final_doctor_email}, {'_id': 0}))
    for r in other_rows:
        if (r.get('appointment_id') or '') == appointment_id:
            continue
        if _normalize_scheduled_time(r.get('scheduled_time')) != slot:
            continue
        st = (r.get('status') or 'pending').strip().lower()
        if st in active_statuses:
            raise HTTPException(status_code=409, detail='Doctor already has an appointment at this time')

    doctor = db['patients'].find_one({'email': final_doctor_email, 'role': 'doctor'})
    if not doctor:
        doctor = db['doctors'].find_one({'email': final_doctor_email})
    if not doctor:
        raise HTTPException(status_code=404, detail='Doctor not found')

    approved_at = time.time()
    res = db['appointments'].update_one(
        {'appointment_id': appointment_id},
        {'$set': {
            'status': 'approved',
            'doctor_email': final_doctor_email,
            'approved_at': approved_at,
        }}
    )
    if getattr(res, 'matched_count', 0) == 0:
        raise HTTPException(status_code=404, detail='Appointment not found')

    patient_email = appt.get('patient_email')
    if patient_email:
        try:
            db['patients'].update_one({'email': patient_email}, {'$set': {'assigned_doctor_email': final_doctor_email}})
        except Exception:
            pass

    log_security_event(f"Admin approved appointment {appointment_id} -> doctor={final_doctor_email}")

    rejected_at = time.time()
    for r in other_rows:
        other_id = (r.get('appointment_id') or '').strip()
        if not other_id or other_id == appointment_id:
            continue
        if _normalize_scheduled_time(r.get('scheduled_time')) != slot:
            continue
        if (r.get('status') or 'pending').strip().lower() != 'pending':
            continue
        try:
            db['appointments'].update_one(
                {'appointment_id': other_id},
                {'$set': {
                    'status': 'rejected',
                    'rejected_at': rejected_at,
                    'rejection_reason': 'Time slot already taken',
                    'rejected_by': 'system'
                }}
            )
        except Exception:
            pass

    copy = dict(appt)
    copy.pop('_id', None)
    copy['status'] = 'approved'
    copy['doctor_email'] = final_doctor_email
    copy['approved_at'] = approved_at
    return copy


@router.put('/appointments/{appointment_id}/reject')
def admin_reject_appointment(appointment_id: str, payload: dict, request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    """Reject a pending appointment with a reason."""
    require_admin(authorization, x_api_key, request)

    reason = (payload.get('reason') or '').strip()
    if not reason:
        raise HTTPException(status_code=400, detail='reason is required')

    db = get_database()
    appt = db['appointments'].find_one({'appointment_id': appointment_id})
    if not appt:
        raise HTTPException(status_code=404, detail='Appointment not found')

    if (appt.get('status') or 'pending') != 'pending':
        raise HTTPException(status_code=400, detail='Only pending appointments can be rejected')

    rejected_at = time.time()
    res = db['appointments'].update_one(
        {'appointment_id': appointment_id},
        {'$set': {
            'status': 'rejected',
            'rejected_at': rejected_at,
            'rejection_reason': reason,
            'rejected_by': 'admin',
        }}
    )
    if getattr(res, 'matched_count', 0) == 0:
        raise HTTPException(status_code=404, detail='Appointment not found')

    log_security_event(f"Admin rejected appointment {appointment_id} reason={reason}")
    copy = dict(appt)
    copy.pop('_id', None)
    copy['status'] = 'rejected'
    copy['rejected_at'] = rejected_at
    copy['rejection_reason'] = reason
    copy['rejected_by'] = 'admin'
    return copy