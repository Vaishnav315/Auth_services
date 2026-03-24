from sqlalchemy import Column, String
from database import Base

class User(Base):
    __tablename__ = "users"

    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)
