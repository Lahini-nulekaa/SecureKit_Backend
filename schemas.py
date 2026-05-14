# backend/schemas.py
from pydantic import BaseModel

# NOTE: using plain `str` for email to avoid requiring the optional
# `email-validator` dependency during local development. Replace with
# `EmailStr` if you install `pydantic[email]` in production.

# This acts like your Mongoose Schema
class PatientSignup(BaseModel):
    full_name: str
    email: str
    password: str
    age: int
    medical_history: str = "None" # Optional field with default value


class DoctorSignup(BaseModel):
    full_name: str
    email: str
    password: str
    license_id: str
    # Optional field for better UX (defaults used if omitted)
    department: str = "General Medicine"
