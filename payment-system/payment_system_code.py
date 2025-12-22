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

SessionLocal = sessionmaker(
    autocommit=False
    autoflush=False
    bind=engine
)
Base = declarative_base()

# ==================== НАСТРОЙКА БЕЗОПАСНОСТИ ====================
pwd_context = CryptoContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ==================== ПЕРЕЧИСЛЕНИЯ (ENUMS) ====================
# Enums - это ограниченные наборы значений, как варианты в меню
# Используем для полей, которые могут иметь только определенные значения
class TransactionType(str, Enum):
    TRANSFER = "transfer" # Перевод денег с одного счета на другой
    DEPOSIT = "deposit"  # Пополнение счета (внесение денег)
    WITHDRAWAL = "withdrawal" # Снятие денег со счета
    PAYMENT = "payment" # Оплата товара или услуги
    REFUND = "refund" # Возврат денег
    
class TransactionStatus(str, Enum):
    PENDING = "pending" #Транзакция создана, но еще не обрабатывается
    PROCESSING = "processing" #Транзакция в процессе обработки
    COMPLETED = "completed" #Тразакция успешно завершена
    FAILED = "failed" #Транзакция не удалась
    CANCELLED = "cancelled" #Тразакция отменена

class AccountType(str, Enum):
    CHECKING = "checking" #Текущий расчетный счет
    SAVING = "savings" #Сберегательный счет
    BUSSINESS = "bussiness" #Бизнес-счет
    CREDIT = "credit" #Кредитный счет
    
class AccountStatus(str, Enum):
    ACTIVE = "active" # Счет доступен для всех операций
    INACTIVE = "inactive" # Счет существует, но операции заблокированы
    FROZEN = "frozen" # Счет заморожен (например, по решению суда)
    CLOSED = "closed" # Счет закрыт

# ==================== МОДЕЛИ БАЗЫ ДАННЫХ ====================
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
    
    # user_id - уникальный идентификатор пользователя
    # Column() создает колонку в таблице
    # Integer - тип данных SQL "целое число"
    # primary_key=True - это ПЕРВИЧНЫЙ КЛЮЧ (уникальный идентификатор записи)
    # index=True - создает индекс для быстрого поиска по этому полю
    user_id = Column(Integer, primary_key=True, index=True)
    
    # username - логин пользователя (уникальный, обязательный)
    # String - строка переменной длины
    # unique=True - значение должно быть уникальным во всей таблице
    # nullable=False - поле НЕ может быть пустым (NOT NULL в SQL)
    username = Column(String, unique=True, index=True, nullable=False)
    
    # email - электронная почта (уникальная, обязательная)
    email = Column(String, nullable=False)