# models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, func, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)

    # Flag to distinguish regular users from administrators
    is_admin        = Column(Boolean, nullable=False, default=False)

    entries = relationship("Entry", back_populates="owner")

class Entry(Base):
    __tablename__ = "entries"

    id            = Column(Integer, primary_key=True, index=True)
    UserName      = Column(String,  nullable=False, default="dummy")
    AppName       = Column(String,  nullable=False, default="dummy")
    prompt        = Column(String,  nullable=False, default="dummy")
    prompt_name   = Column(String,  nullable=False, default="dummy")
    user_prompt   = Column(String,  nullable=False, default="dummy")
    group_name    = Column(String,  nullable=False, default="dummy")
    sample_output = Column(String,  nullable=False, default="dummy")
    tags          = Column(String,  nullable=False, default="default") 
    createdBy     = Column(String,  nullable=False, default="dummy")
    modifiedBy    = Column(String,  nullable=False, default="dummy")
    active        = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    owner    = relationship("User", back_populates="entries")

    def __repr__(self):
        return f"<Entry id={self.id} UserName={self.UserName}>"
