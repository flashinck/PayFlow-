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

# ==================== НАСТРОЙКА КОНФИГУРАЦИИ ====================
DATEBASE_URL = os.getenv("DATEBASE_URL", "postgresql://payflow_user:payflow_user:payflow_pass@localhost/payflow_db")
SECRET_KEY = os.getenv("SECRET_KEY", "payflow-super-secret-key-change-in-prodaction-12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== НАСТРОЙКА БАЗЫ ДАННЫХ ====================
engine = create_engine(
    DATABASE_URL,
    echo=False
)