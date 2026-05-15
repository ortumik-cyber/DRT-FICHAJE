from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib, os, json, uuid, unicodedata
from datetime import datetime, timedelta
from jose import jwt, JWTError

# ── CONFIG ────────────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET", "cambia-esto-en-render")
JWT_ALGORITHM = "HS256"
JWT_HOURS     = 12
RETENTION_YEARS = 4

app = FastAPI(title="DRT Fichaje API", docs_url=None, redoc_url=None)

# ── FIREBASE INIT ─────────────────────────────────────────────
_creds_json = os.environ.get("FIREBASE_CREDENTIALS")
if _creds_json:
    _cred = credentials.Certificate(json.loads(_creds_json))
    firebase_admin.initialize_app(_cred)
    db = firestore.client()
else:
    db = None  # desarrollo local sin Firebase

# ── HELPERS ───────────────────────────────────────────────────
def norm(s: str) -> str:
    return unicodedata.normalize("NFD", s.strip().lower()).encode("ascii", "ignore").decode()

def uid() -> str:
    return uuid.uuid4().hex[:20]

def hash_pwd(p: str) -> str:
    return hashlib.sha256(f"DRT:{p}".encode()).hexdigest()

def get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "N/D")

def audit_log(event: str, user_id: str, details: str = ""):
    db.collection("audit").add({
        "type": event, "userId": user_id,
        "ts": datetime.utcnow().isoformat(), "details": details
    })

def check_db():
    if not db:
        raise HTTPException(503, "Base de datos no disponible")

# ── AUTH ──────────────────────────────────────────────────────
bearer = HTTPBearer()

def make_token(user_id: str, role: str) -> str:
    return jwt.encode(
        {"sub": user_id, "role": role,
         "exp": datetime.utcnow() + timedelta(hours=JWT_HOURS)},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Token inválido o expirado")

def require_admin(payload=Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(403, "Acceso denegado — se requiere rol administrador")
    return payload

# ── MODELOS ───────────────────────────────────────────────────
class LoginReq(BaseModel):
    nombre: str
    password: str

class ChangePwdReq(BaseModel):
    new_pwd: str

class FicharReq(BaseModel):
    lat: Optional[float] = None
    lon: Optional[float] = None
    acc: Optional[float] = None

class SetupReq(BaseModel):
    nombre: str
    apellido: str
    email: Optional[str] = ""
    dept: Optional[str] = "Dirección"
    pwd: str

class CreateUserReq(BaseModel):
    nombre: str
    apellido: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    dept: Optional[str] = ""
    role: str = "employee"
    temp_pwd: str

class ResetPwdReq(BaseModel):
    user_id: str
    new_pwd: str

class UpdateUserReq(BaseModel):
    active: Optional[bool] = None
    dept: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

# ── ENDPOINTS PÚBLICOS ────────────────────────────────────────
@app.get("/api/status")
async def status():
    if not db:
        return {"configured": False}
    has = bool(list(db.collection("users").limit(1).stream()))
    return {"configured": has}

@app.post("/api/setup")
async def setup(data: SetupReq):
    check_db()
    if list(db.collection("users").limit(1).stream()):
        raise HTTPException(400, "El sistema ya está configurado")
    if len(data.pwd) < 6:
        raise HTTPException(400, "Contraseña mínimo 6 caracteres")

    fullname = f"{data.nombre.strip()} {data.apellido.strip()}"
    user_id  = uid()
    user = {
        "nombre": data.nombre.strip(), "apellido": data.apellido.strip(),
        "fullname": fullname, "loginKey": norm(fullname),
        "email": data.email or "", "phone": "", "dept": data.dept or "Dirección",
        "role": "admin", "hash": hash_pwd(data.pwd),
        "active": True, "firstLogin": False, "failedAttempts": 0,
        "createdAt": datetime.utcnow().isoformat()
    }
    db.collection("users").document(user_id).set(user)
    audit_log("SETUP", user_id, "Sistema inicializado")
    token = make_token(user_id, "admin")
    return {"token": token, "user": {**{k:v for k,v in user.items() if k!="hash"}, "id": user_id}}

@app.post("/api/auth/login")
async def login(data: LoginReq, request: Request):
    check_db()
    key   = norm(data.nombre)
    docs  = list(db.collection("users").where("loginKey", "==", key).limit(1).stream())
    if not docs:
        raise HTTPException(401, "Empleado no encontrado. Escribe nombre y apellido exactos.")
    u     = {"id": docs[0].id, **docs[0].to_dict()}

    if not u.get("active", True):
        raise HTTPException(403, "Cuenta desactivada. Contacta con el administrador.")

    locked = u.get("lockedUntil")
    if locked and datetime.fromisoformat(locked) > datetime.utcnow():
        mins = max(1, int((datetime.fromisoformat(locked) - datetime.utcnow()).seconds / 60) + 1)
        raise HTTPException(429, f"Cuenta bloqueada {mins} min por intentos fallidos.")

    if hash_pwd(data.password) != u.get("hash"):
        failed = u.get("failedAttempts", 0) + 1
        upd    = {"failedAttempts": failed}
        if failed >= 3:
            upd["lockedUntil"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        db.collection("users").document(u["id"]).update(upd)
        raise HTTPException(401, f"Contraseña incorrecta. Intento {failed}/3.")

    db.collection("users").document(u["id"]).update({"failedAttempts": 0, "lockedUntil": None})
    audit_log("LOGIN", u["id"], f"Login: {u['fullname']}")
    token = make_token(u["id"], u.get("role", "employee"))
    return {
        "token": token,
        "user": {
            "id": u["id"], "nombre": u["nombre"], "apellido": u["apellido"],
            "fullname": u["fullname"], "email": u.get("email",""),
            "phone": u.get("phone",""), "dept": u.get("dept",""),
            "role": u.get("role","employee"), "firstLogin": u.get("firstLogin", False),
            "createdAt": u.get("createdAt","")
        }
    }

# ── ENDPOINTS EMPLEADO ────────────────────────────────────────
@app.get("/api/me")
async def get_me(payload=Depends(verify_token)):
    check_db()
    doc = db.collection("users").document(payload["sub"]).get()
    if not doc.exists:
        raise HTTPException(404, "Usuario no encontrado")
    u = doc.to_dict()
    return {k:v for k,v in {**u, "id": doc.id}.items() if k != "hash"}

@app.post("/api/auth/change-password")
async def change_password(data: ChangePwdReq, payload=Depends(verify_token)):
    check_db()
    if len(data.new_pwd) < 6:
        raise HTTPException(400, "Mínimo 6 caracteres")
    db.collection("users").document(payload["sub"]).update({
        "hash": hash_pwd(data.new_pwd), "firstLogin": False
    })
    audit_log("FIRST_PWD", payload["sub"], "Contraseña personal creada")
    return {"ok": True}

@app.post("/api/fichar")
async def fichar(data: FicharReq, request: Request, payload=Depends(verify_token)):
    check_db()
    user_id = payload["sub"]
    ip      = get_ip(request)

    ultimos = list(
        db.collection("fichajes")
        .where("uid", "==", user_id)
        .order_by("ts", direction=firestore.Query.DESCENDING)
        .limit(1).stream()
    )
    ultimo = ultimos[0].to_dict() if ultimos else None
    tipo   = "salida" if (ultimo and ultimo.get("tipo") == "entrada") else "entrada"

    if tipo == "entrada":
        hoy = datetime.utcnow().date().isoformat()
        entradas_hoy = list(
            db.collection("fichajes")
            .where("uid", "==", user_id)
            .where("tipo", "==", "entrada")
            .stream()
        )
        count = sum(1 for f in entradas_hoy if f.to_dict().get("ts","").startswith(hoy))
        if count >= 3:
            raise HTTPException(400, "Máximo 3 jornadas registradas hoy. Contacta con el administrador.")

    ts = datetime.utcnow().isoformat()
    db.collection("fichajes").add({
        "uid": user_id, "tipo": tipo, "ts": ts,
        "ip": ip, "lat": data.lat, "lon": data.lon, "acc": data.acc
    })
    audit_log("FICHAJE", user_id, tipo)
    return {"ok": True, "tipo": tipo, "ts": ts}

@app.get("/api/fichajes")
async def mis_fichajes(payload=Depends(verify_token)):
    check_db()
    docs = db.collection("fichajes").where("uid", "==", payload["sub"]).order_by("ts").stream()
    return [{"id": d.id, **d.to_dict()} for d in docs]

# ── ENDPOINTS ADMIN ───────────────────────────────────────────
@app.get("/api/admin/empleados")
async def admin_empleados(payload=Depends(require_admin)):
    check_db()
    docs = db.collection("users").stream()
    return [{"id": d.id, **{k:v for k,v in d.to_dict().items() if k!="hash"}} for d in docs]

@app.post("/api/admin/empleados")
async def admin_crear(data: CreateUserReq, payload=Depends(require_admin)):
    check_db()
    fullname  = f"{data.nombre.strip()} {data.apellido.strip()}"
    login_key = norm(fullname)
    if list(db.collection("users").where("loginKey","==",login_key).limit(1).stream()):
        raise HTTPException(400, "Ya existe un empleado con ese nombre y apellido")
    if len(data.temp_pwd) < 6:
        raise HTTPException(400, "Contraseña mínimo 6 caracteres")

    user_id = uid()
    user = {
        "nombre": data.nombre.strip(), "apellido": data.apellido.strip(),
        "fullname": fullname, "loginKey": login_key,
        "email": data.email or "", "phone": data.phone or "",
        "dept": data.dept or "", "role": data.role,
        "hash": hash_pwd(data.temp_pwd),
        "active": True, "firstLogin": True, "failedAttempts": 0,
        "createdAt": datetime.utcnow().isoformat(), "createdBy": payload["sub"]
    }
    db.collection("users").document(user_id).set(user)
    audit_log("CREATE_USER", payload["sub"], f"Creado: {fullname}")
    return {"id": user_id, **{k:v for k,v in user.items() if k!="hash"}}

@app.put("/api/admin/empleados/{user_id}")
async def admin_update(user_id: str, data: UpdateUserReq, payload=Depends(require_admin)):
    check_db()
    upd = {k:v for k,v in data.dict().items() if v is not None}
    if upd:
        db.collection("users").document(user_id).update(upd)
        audit_log("UPDATE_USER", payload["sub"], f"Actualizado: {user_id}")
    return {"ok": True}

@app.post("/api/admin/reset-pwd")
async def admin_reset_pwd(data: ResetPwdReq, payload=Depends(require_admin)):
    check_db()
    if len(data.new_pwd) < 6:
        raise HTTPException(400, "Mínimo 6 caracteres")
    if not db.collection("users").document(data.user_id).get().exists:
        raise HTTPException(404, "Usuario no encontrado")
    db.collection("users").document(data.user_id).update({
        "hash": hash_pwd(data.new_pwd),
        "firstLogin": True, "failedAttempts": 0, "lockedUntil": None
    })
    audit_log("PWD_RESET", payload["sub"], f"Reset: {data.user_id}")
    return {"ok": True}

@app.get("/api/admin/fichajes")
async def admin_fichajes(payload=Depends(require_admin)):
    check_db()
    docs = db.collection("fichajes").order_by("ts", direction=firestore.Query.DESCENDING).stream()
    return [{"id": d.id, **d.to_dict()} for d in docs]

@app.delete("/api/admin/fichajes/{fichaje_id}")
async def admin_del_fichaje(fichaje_id: str, payload=Depends(require_admin)):
    check_db()
    doc = db.collection("fichajes").document(fichaje_id).get()
    if not doc.exists:
        raise HTTPException(404, "Fichaje no encontrado")
    ts = doc.to_dict().get("ts","")
    if ts:
        created = datetime.fromisoformat(ts)
        if (datetime.utcnow() - created).days < RETENTION_YEARS * 365:
            raise HTTPException(403, f"Retención mínima {RETENTION_YEARS} años. No se puede eliminar aún.")
    doc.reference.delete()
    audit_log("DELETE_FICHAJE", payload["sub"], fichaje_id)
    return {"ok": True}

@app.get("/api/admin/auditoria")
async def admin_auditoria(payload=Depends(require_admin)):
    check_db()
    docs = db.collection("audit").order_by("ts", direction=firestore.Query.DESCENDING).limit(500).stream()
    return [{"id": d.id, **d.to_dict()} for d in docs]

@app.get("/api/admin/export")
async def admin_export(payload=Depends(require_admin)):
    check_db()
    users    = [{"id":d.id,**{k:v for k,v in d.to_dict().items() if k!="hash"}} for d in db.collection("users").stream()]
    fichajes = [{"id":d.id,**d.to_dict()} for d in db.collection("fichajes").order_by("ts").stream()]
    auditoria= [{"id":d.id,**d.to_dict()} for d in db.collection("audit").order_by("ts", direction=firestore.Query.DESCENDING).limit(1000).stream()]
    audit_log("EXPORT", payload["sub"], "Exportación datos")
    return {"users": users, "fichajes": fichajes, "audit": auditoria}

# ── FRONTEND ──────────────────────────────────────────────────
import os as _os
_static = _os.path.join(_os.path.dirname(__file__), "static")
if _os.path.isdir(_static):
    app.mount("/static", StaticFiles(directory=_static), name="static")
@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    idx = _os.path.join(_static, "index.html")
    if _os.path.isfile(idx):
        return FileResponse(idx)
    return {"error": "Frontend no encontrado. Crea static/index.html"}
