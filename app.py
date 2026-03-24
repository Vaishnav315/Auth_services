from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import bcrypt
import jwt
from datetime import datetime, timedelta

app = FastAPI()

SECRET_KEY = "super_secret_key_123"  # change this later

# Temporary database (RAM only)
users = []

# Models
class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# REGISTER
@app.post("/register")
def register(user: UserRegister):
    for u in users:
        if u["email"] == user.email:
            raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    users.append({
        "name": user.name,
        "email": user.email,
        "password": hashed_pw
    })

    return {"message": "User registered successfully"}

# LOGIN
@app.post("/login")
def login(user: UserLogin):
    for u in users:
        if u["email"] == user.email:
            if bcrypt.checkpw(user.password.encode(), u["password"]):
                token = jwt.encode(
                    {
                        "email": user.email,
                        "exp": datetime.utcnow() + timedelta(days=1)
                    },
                    SECRET_KEY,
                    algorithm="HS256"
                )
                return {"token": token}
            else:
                raise HTTPException(status_code=400, detail="Invalid password")

    raise HTTPException(status_code=400, detail="Invalid email")

# VERIFY TOKEN
@app.get("/verify")
def verify(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="No token")

    token = authorization.split(" ")[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {"valid": True, "user": decoded}
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# ROOT
@app.get("/")
def root():
    return {"message": "API is running 🚀"}