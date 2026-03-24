import re
import logging
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import engine, Base, get_db
from models import User, RefreshToken
import auth

# Initialize DB tables
Base.metadata.create_all(bind=engine)

# Setup slowapi rate limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Security: Set proper CORS origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Replace with specific domains in intense production like ["https://myapp.com"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Pydantic Schemas with advanced validations
class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

    @validator('password')
    def validate_password_strength(cls, value):
        if len(value) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Za-z]', value):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'\d', value):
            raise ValueError('Password must contain at least one number')
        return value

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenRefresh(BaseModel):
    refresh_token: str

@app.post("/register")
@limiter.limit("3/minute")
def register(request: Request, user: UserRegister, db: Session = Depends(get_db)):
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            logger.warning(f"Registration attempt for existing email: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        
        hashed_pw = auth.hash_password(user.password)
        new_user = User(email=user.email, name=user.name, password=hashed_pw)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        logger.info(f"New user registered: {user.email}")
        return {"success": True, "message": "User registered successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Internal structure error on register: {e}")
        raise HTTPException(status_code=500, detail="An error occurred processing the registration.")

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not auth.verify_password(user.password, db_user.password):
        logger.warning(f"Failed login attempt for: {user.email}")
        # generic message for security
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    access_token = auth.create_access_token({"sub": db_user.email})
    refresh_token = auth.create_refresh_token(db_user.email, db)
    
    logger.info(f"Successful login for: {user.email}")
    return {
        "success": True, 
        "access_token": access_token, 
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh-token")
def refresh_token(data: TokenRefresh, db: Session = Depends(get_db)):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == data.refresh_token).first()
    
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    if db_token.expires_at < datetime.utcnow():
        db.delete(db_token)
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # generate new access token
    new_access_token = auth.create_access_token({"sub": db_token.user_email})
    return {
        "success": True, 
        "access_token": new_access_token, 
        "token_type": "bearer"
    }

@app.post("/logout")
def logout(data: TokenRefresh, db: Session = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == data.refresh_token,
        RefreshToken.user_email == current_user.email
    ).first()
    
    if db_token:
        db.delete(db_token)
        db.commit()
        
    logger.info(f"Logged out user: {current_user.email}")
    return {"success": True, "message": "Logged out successfully"}

# Protected Environment Route Tests
@app.get("/user-profile")
def get_user_profile(current_user: User = Depends(auth.get_current_user)):
    return {
        "success": True, 
        "user": {
            "email": current_user.email, 
            "name": current_user.name
        }
    }

@app.get("/secure-data")
def get_secure_data(current_user: User = Depends(auth.get_current_user)):
    return {
        "success": True,
        "message": f"Hello {current_user.name}, you have verified access to protected data."
    }

@app.get("/")
def root():
    return {"message": "Secure Auth API is running! 🚀"}
