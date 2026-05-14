# backend/database.py
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
    PyMongoError,
    ConfigurationError,
)
import threading
import json
import uuid
from pathlib import Path

load_dotenv()

# Connection string — prefer environment variable in production
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("CRITICAL ERROR: MONGO_URI environment variable is not set.")
# When REQUIRE_DB is set to a truthy value, the app will fail startup if
# MongoDB is unreachable. Useful for production deployments.
REQUIRE_DB = os.getenv("REQUIRE_DB", "false").lower() in ("1", "true", "yes")

# Shared state
_client = None
_db = None
_lock = threading.Lock()

def _connect():
    global _client, _db
    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _db = _client["secure_health_db"]
        _client.admin.command('ping')
        print("✅ MONGODB CONNECTION: SUCCESSFUL")
    except (PyMongoError, OSError):
        _client = None
        _db = None
        msg = "❌ MONGODB CONNECTION: FAILED (Check if MongoDB is reachable)."
        if REQUIRE_DB:
            # In production we want startup to fail fast so issues are visible.
            print(msg + " REQUIRE_DB=true, aborting startup.")
            raise
        # Otherwise fall back to file storage for local development.
        print(msg + " Falling back to file storage.")
        try:
            _db = _create_file_db()
            print("ℹ️ Using file-based fallback DB at backend/data/patients.json")
        except Exception as e:
            print(f"❌ Failed to create fallback DB: {e}")

def get_database():
    """Return a MongoDB database instance. Attempts to connect on first call.

    Raises a RuntimeError if the connection cannot be established.
    """
    global _db
    if _db is None:
        with _lock:
            if _db is None:
                _connect()
    if _db is None:
        raise RuntimeError("Database connection not available")
    return _db


def _create_file_db():
    """Return a lightweight file-backed DB object with a 'patients' collection.

    The returned object supports indexing like a pymongo Database: db['patients'].
    """
    data_dir = Path(__file__).resolve().parent / 'data'
    data_dir.mkdir(parents=True, exist_ok=True)
    patients_file = data_dir / 'patients.json'
    if not patients_file.exists():
        patients_file.write_text('[]', encoding='utf-8')

    appointments_file = data_dir / 'appointments.json'
    if not appointments_file.exists():
        appointments_file.write_text('[]', encoding='utf-8')

    doctors_file = data_dir / 'doctors.json'
    if not doctors_file.exists():
        doctors_file.write_text('[]', encoding='utf-8')

    doctor_applications_file = data_dir / 'doctor_applications.json'
    if not doctor_applications_file.exists():
        doctor_applications_file.write_text('[]', encoding='utf-8')

    class FakeCollection:
        def __init__(self, path: Path):
            self.path = path
            self._lock = threading.Lock()

        def _read_all(self):
            with self._lock:
                try:
                    return json.loads(self.path.read_text(encoding='utf-8') or '[]')
                except Exception:
                    return []

        def _write_all(self, docs):
            with self._lock:
                self.path.write_text(json.dumps(docs, indent=2), encoding='utf-8')

        def find_one(self, query: dict):
            docs = self._read_all()
            # support simple equality on top-level fields
            for d in docs:
                match = True
                for k, v in query.items():
                    if d.get(k) != v:
                        match = False
                        break
                if match:
                    return d
            return None

        def find(self, query: dict | None = None, projection: dict | None = None):
            query = query or {}
            docs = self._read_all()
            out = []
            for d in docs:
                match = True
                for k, v in query.items():
                    if d.get(k) != v:
                        match = False
                        break
                if not match:
                    continue

                row = dict(d)
                if projection:
                    # Support exclusion-only projection like {"_id": 0, "password": 0}
                    excludes = [k for k, v in projection.items() if v == 0]
                    for k in excludes:
                        row.pop(k, None)
                out.append(row)
            return out

        def insert_one(self, doc: dict):
            docs = self._read_all()
            # emulate ObjectId by using uuid4 hex
            obj = dict(doc)
            obj['_id'] = uuid.uuid4().hex
            docs.append(obj)
            self._write_all(docs)
            class Result:
                def __init__(self, inserted_id):
                    self.inserted_id = inserted_id
            return Result(obj['_id'])

        def update_one(self, query: dict, update: dict):
            docs = self._read_all()
            matched = 0
            modified = 0
            set_doc = (update or {}).get('$set') or {}
            for i, d in enumerate(docs):
                match = True
                for k, v in query.items():
                    if d.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
                matched = 1
                new_d = dict(d)
                for k, v in set_doc.items():
                    if new_d.get(k) != v:
                        new_d[k] = v
                        modified = 1
                docs[i] = new_d
                break
            if matched:
                self._write_all(docs)

            class Result:
                def __init__(self, matched_count, modified_count):
                    self.matched_count = matched_count
                    self.modified_count = modified_count

            return Result(matched, modified)

        def delete_one(self, query: dict):
            docs = self._read_all()
            deleted = 0
            for i, d in enumerate(docs):
                match = True
                for k, v in query.items():
                    if d.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
                docs.pop(i)
                deleted = 1
                break
            if deleted:
                self._write_all(docs)

            class Result:
                def __init__(self, deleted_count):
                    self.deleted_count = deleted_count

            return Result(deleted)

    class FakeDB:
        def __init__(self, patients_path: Path):
            self._patients = FakeCollection(patients_path)
            self._doctors = FakeCollection(doctors_file)
            self._doctor_applications = FakeCollection(doctor_applications_file)
            self._appointments = FakeCollection(appointments_file)

        # token storage path lives alongside patients.json
        def token_path(self):
            return self._patients.path.with_name('tokens.json')

        def store_token(self, token: str, email: str):
            p = self.token_path()
            with self._patients._lock:
                try:
                    tokens = json.loads(p.read_text(encoding='utf-8')) if p.exists() else {}
                except Exception:
                    tokens = {}
                tokens[token] = {"email": email}
                p.write_text(json.dumps(tokens, indent=2), encoding='utf-8')

        def get_email_by_token(self, token: str):
            p = self.token_path()
            if not p.exists():
                return None
            try:
                tokens = json.loads(p.read_text(encoding='utf-8'))
                entry = tokens.get(token)
                return entry.get('email') if entry else None
            except Exception:
                return None

        def __getitem__(self, name: str):
            # support both 'patients' and 'users' in fallback mode
            if name in ('patients', 'users'):
                return self._patients
            if name == 'doctors':
                return self._doctors
            if name in ('doctor_applications', 'doctorApplications'):
                return self._doctor_applications
            if name == 'appointments':
                return self._appointments
            raise KeyError(name)

    return FakeDB(patients_file)


def get_users_collection():
    """Return a users collection compatible object for both real MongoDB and fallback DB."""
    db = get_database()
    return db['users']
