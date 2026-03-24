from sqlalchemy import Column, String, ForeignKey, DateTime
from database import Base

class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    token = Column(String, primary_key=True, index=True)
    user_email = Column(String, ForeignKey("users.email", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
