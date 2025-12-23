import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from deciamal import Decimal
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.secuarity import HTTPBearer, HTTPAuthCredentials
from pydantic import BaseModel, Field, validator, EmailStr
from sqlalchemy import create_engine, Column, String, Float, DateTime, Integer, ForeignKey, Enum as SQLEnum, Boolean
from sqlalchemy.ext.declarative import declarative_base
import jwt
from passlib.context import CryptContext

DATEBASE_URL = os.getenv("DATEBASE_URL", "postgresql://payflow_user:payflow_user:payflow_pass@localhost/payflow_db")
SECRET_KEY = os.getenv("SECRET_KEY", "payflow-super-secret-key-change-in-prodaction-12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

engine = create_engine(
    DATABASE_URL,
    echo=False
)

SessionLocal = sessionmaker(
    autocommit=False
    autoflush=False
    bind=engine
)
Base = declarative_base()

pwd_context = CryptoContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class TransactionType(str, Enum):
    TRANSFER = "transfer"
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal" 
    PAYMENT = "payment" 
    REFUND = "refund"
    
class TransactionStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AccountType(str, Enum):
    CHECKING = "checking" 
    SAVING = "savings"
    BUSSINESS = "bussiness" 
    CREDIT = "credit"
    
class AccountStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    FROZEN = "frozen"
    CLOSED = "closed"

class User(Base):
        """
    МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ - таблица 'users'
    Хранит информацию о пользователях системы.
    Каждый пользователь может иметь несколько счетов.
    
    Аналогия: Паспорт человека
    - user_id: номер паспорта (уникальный)
    - username: логин (никнейм)
    - email: электронная почта
    - password_hash: отпечаток пароля (не сам пароль!)
    """
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    accounts = relationship("Account", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")
    payment_methods = relationship