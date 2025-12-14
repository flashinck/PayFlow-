"""
payment_system.py - ПОЛНОЦЕННАЯ ПЛАТЕЖНАЯ СИСТЕМА НА PYTHON

ЧТО ЭТО ЗА ФАЙЛ?
Это основной файл приложения, который содержит все компоненты платежной системы:
1. Модели базы данных - описывают таблицы и связи между ними
2. Бизнес-логика (сервисы) - содержат правила обработки операций
3. API эндпоинты - точки входа для клиентов (мобильные приложения, веб-сайты)
4. Валидаторы - проверяют корректность данных перед обработкой
5. Логирование и аудит - отслеживают все действия в системе
6. Аналитика - собирает статистику для отчетов

ПОЧЕМУ ИМЕННО ТАКАЯ АРХИТЕКТУРА?
Этот код использует "слоистую архитектуру", где каждый слой отвечает за свою часть:
- Модели БД работают с данными
- Сервисы содержат бизнес-правила  
- API обрабатывает HTTP запросы
Такой подход упрощает поддержку, тестирование и развитие системы.
"""

# ==================== ИМПОРТЫ ====================
# Сначала импортируем стандартные библиотеки Python (идут в комплекте)
import os  # Для работы с операционной системой: чтение переменных окружения, работа с файлами
import json  # Для работы с JSON форматом: сериализация/десериализация данных
import logging  # Для записи логов: отслеживание работы приложения, отладка ошибок
import hashlib  # Для хеширования данных (шифрования)
import secrets  # Для генерации безопасных случайных значений (токены, ключи)
from datetime import datetime, timedelta  # Работа с датой и временем: сроки действия, периоды
from typing import Optional, List, Dict, Any  # Аннотации типов для понятности кода
from enum import Enum  # Для создания перечислений (фиксированных наборов значений)
from decimal import Decimal  # Для точных денежных вычислений (хотя используем float для простоты)

# ==================== ИМПОРТЫ СТОРОННИХ БИБЛИОТЕК ====================
# Эти библиотеки нужно установить через pip install

# FastAPI - современный веб-фреймворк для создания API
from fastapi import FastAPI, HTTPException, Depends, status
# HTTPBearer - схема аутентификации через Bearer токен (токен в заголовке Authorization)
from fastapi.security import HTTPBearer, HTTPAuthCredentials

# Pydantic - библиотека для валидации данных и создания схем
from pydantic import BaseModel, Field, validator, EmailStr

# SQLAlchemy - ORM (Object-Relational Mapping) для работы с базами данных
# ORM позволяет работать с БД как с Python объектами, а не SQL запросами
from sqlalchemy import create_engine, Column, String, Float, DateTime, Integer, ForeignKey, Enum as SQLEnum, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

# PyJWT - для работы с JWT (JSON Web Tokens) - стандарт для аутентификации
import jwt

# Passlib - для безопасного хеширования паролей
from passlib.context import CryptContext


# ==================== КОНФИГУРАЦИЯ СИСТЕМЫ ====================
# Здесь настраиваются основные параметры системы

# DATABASE_URL - строка подключения к базе данных
# os.getenv() читает значение из переменной окружения, если её нет - использует значение по умолчанию
# Формат: postgresql://user:password@host:port/database_name
# Зачем переменные окружения? Чтобы не хранить пароли в коде, можно менять настройки без изменения кода
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/payment_system")

# SECRET_KEY - секретный ключ для подписи JWT токенов
# ВНИМАНИЕ: В продакшене должен быть длинным, сложным и храниться в секрете!
# Если злоумышленник узнает этот ключ, он сможет создавать поддельные токены
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

# ALGORITHM - алгоритм шифрования для JWT
# HS256 - HMAC с SHA-256, симметричное шифрование (один ключ для подписи и проверки)
ALGORITHM = "HS256"

# Время жизни access токена в минутах
# Access токен - это временный токен для доступа к API
# 30 минут - баланс между безопасностью и удобством (не нужно часто вводить пароль)
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================
# Логирование - запись событий в системе (ошибки, информация, предупреждения)

# basicConfig() настраивает базовые параметры логирования
# level=logging.INFO означает, что будут записываться сообщения уровня INFO и выше (WARNING, ERROR, CRITICAL)
logging.basicConfig(level=logging.INFO)

# Создаем логгер для этого модуля
# Каждый модуль может иметь свой логгер, чтобы понимать откуда пришло сообщение
logger = logging.getLogger(__name__)


# ==================== НАСТРОЙКА БАЗЫ ДАННЫХ ====================

# Создаем "движок" базы данных - основной интерфейс SQLAlchemy к БД
# echo=False отключает вывод SQL запросов в консоль (для продакшена)
engine = create_engine(DATABASE_URL, echo=False)

# Создаем фабрику сессий
# Сессия - это область взаимодействия с БД (как транзакция)
SessionLocal = sessionmaker(
    autocommit=False,  # Автоматически не коммитим изменения
    autoflush=False,   # Автоматически не сбрасываем (flush) изменения
    bind=engine        # Привязываем к движку
)

# Базовый класс для всех моделей
# Все наши классы таблиц будут наследоваться от Base
Base = declarative_base()


# ==================== НАСТРОЙКА БЕЗОПАСНОСТИ ====================

# CryptContext - контекст для хеширования паролей
# schemes=["bcrypt"] - используем алгоритм bcrypt (один из самых безопасных для паролей)
# deprecated="auto" - автоматически помечает устаревшие хеши
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTPBearer - схема аутентификации
# Клиент должен отправлять токен в заголовке: Authorization: Bearer <токен>
security = HTTPBearer()


# ==================== ПЕРЕЧИСЛЕНИЯ (ENUMS) ====================
# Enums - это классы с фиксированным набором значений
# Используются для ограничения возможных значений полей

class TransactionType(str, Enum):
    """
    Типы транзакций в платежной системе.
    str, Enum означает что значения будут строками.
    """
    TRANSFER = "transfer"      # Перевод денег с одного счета на другой
    DEPOSIT = "deposit"        # Внесение денег на счет (без указания отправителя)
    WITHDRAWAL = "withdrawal"  # Снятие денег со счета (без указания получателя)
    PAYMENT = "payment"        # Оплата товара/услуги
    REFUND = "refund"          # Возврат денег


class TransactionStatus(str, Enum):
    """Статусы транзакций - отслеживание жизненного цикла операции"""
    PENDING = "pending"        # Создана, но еще не обрабатывается
    PROCESSING = "processing"  # В процессе обработки
    COMPLETED = "completed"    # Успешно завершена
    FAILED = "failed"          # Не удалась (ошибка, недостаточно средств и т.д.)
    CANCELLED = "cancelled"    # Отменена пользователем или системой


class AccountType(str, Enum):
    """Типы банковских счетов"""
    CHECKING = "checking"   # Текущий (расчетный) счет - для повседневных операций
    SAVINGS = "savings"     # Сберегательный счет - для накоплений
    BUSINESS = "business"   # Бизнес-счет - для предпринимателей
    CREDIT = "credit"       # Кредитный счет - с возможностью уйти в минус


class AccountStatus(str, Enum):
    """Статусы счетов - определяют доступность операций"""
    ACTIVE = "active"    # Счет доступен для всех операций
    INACTIVE = "inactive" # Счет существует, но операции заблокированы
    FROZEN = "frozen"    # Счет заморожен (например, по решению суда)
    CLOSED = "closed"    # Счет закрыт


# ==================== МОДЕЛИ БАЗЫ ДАННЫХ ====================
# Модели - это Python классы, которые представляют таблицы в базе данных
# SQLAlchemy автоматически создаст соответствующие SQL таблицы

class User(Base):
    """
    МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ
    Хранит информацию о пользователях системы.
    Каждый пользователь может иметь несколько счетов.
    """
    __tablename__ = "users"  # Имя таблицы в базе данных
    
    # ===== ПОЛЯ ТАБЛИЦЫ =====
    
    # user_id - уникальный идентификатор пользователя
    # Column() создает колонку в таблице
    # Integer - тип данных "целое число"
    # primary_key=True - это первичный ключ (уникальный идентификатор записи)
    # index=True - создает индекс для ускорения поиска по этому полю
    user_id = Column(Integer, primary_key=True, index=True)
    
    # username - логин пользователя
    # String - строка переменной длины
    # unique=True - значение должно быть уникальным во всей таблице
    # nullable=False - поле обязательно для заполнения (NOT NULL в SQL)
    username = Column(String, unique=True, index=True, nullable=False)
    
    # email - электронная почта
    email = Column(String, unique=True, index=True, nullable=False)
    
    # password_hash - ХЕШ пароля, НЕ сам пароль!
    # Пароли никогда не хранятся в открытом виде
    password_hash = Column(String, nullable=False)
    
    # full_name - полное имя (может быть пустым)
    full_name = Column(String)
    
    # is_active - активен ли пользователь (может ли войти в систему)
    # Boolean - логическое значение (True/False)
    # default=True - значение по умолчанию при создании
    is_active = Column(Boolean, default=True)
    
    # created_at - когда создана запись
    # DateTime - дата и время
    # default=datetime.utcnow - по умолчанию текущее время UTC
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # updated_at - когда запись последний раз обновлялась
    # onupdate=datetime.utcnow - автоматически обновляется при изменении записи
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # ===== СВЯЗИ С ДРУГИМИ ТАБЛИЦАМИ =====
    # relationship() создает связь между таблицами
    
    # accounts - связь "один пользователь → много счетов"
    # "Account" - имя связанной модели
    # back_populates="owner" - создает обратную связь в модели Account
    accounts = relationship("Account", back_populates="owner")
    
    # audit_logs - связь "один пользователь → много логов аудита"
    audit_logs = relationship("AuditLog", back_populates="user")
    
    # payment_methods - связь "один пользователь → много методов оплаты"
    payment_methods = relationship("PaymentMethod", back_populates="user")


class Account(Base):
    """
    МОДЕЛЬ СЧЕТА
    Хранит информацию о банковских счетах.
    Каждый счет принадлежит одному пользователю.
    """
    __tablename__ = "accounts"
    
    account_id = Column(Integer, primary_key=True, index=True)
    
    # user_id - внешний ключ к таблице users
    # ForeignKey("users.user_id") - ссылается на поле user_id в таблице users
    # Это обеспечивает целостность данных: нельзя создать счет для несуществующего пользователя
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    
    # account_type - тип счета, используем наш Enum
    # SQLEnum(AccountType) - преобразует Python Enum в SQL ENUM тип
    account_type = Column(SQLEnum(AccountType), default=AccountType.CHECKING)
    
    # balance - баланс счета
    # Float - число с плавающей точкой (для денег лучше использовать Decimal, но Float проще)
    balance = Column(Float, default=0.0)
    
    # currency - валюта счета (USD, EUR, RUB и т.д.)
    currency = Column(String, default="USD")
    
    # status - статус счета
    status = Column(SQLEnum(AccountStatus), default=AccountStatus.ACTIVE)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # ===== СВЯЗИ =====
    
    # owner - связь "один счет → один пользователь" (обратная к User.accounts)
    owner = relationship("User", back_populates="accounts")
    
    # transactions_from - все транзакции, где этот счет был источником
    # foreign_keys указывает какое поле в Transaction ссылается на этот счет
    transactions_from = relationship("Transaction", foreign_keys="Transaction.source_account_id")
    
    # transactions_to - все транзакции, где этот счет был получателем
    transactions_to = relationship("Transaction", foreign_keys="Transaction.dest_account_id")


class Transaction(Base):
    """
    МОДЕЛЬ ТРАНЗАКЦИИ
    Хранит историю всех денежных операций в системе.
    Это самая важная таблица для аудита и отчетности.
    """
    __tablename__ = "transactions"
    
    transaction_id = Column(Integer, primary_key=True, index=True)
    
    # source_account_id - счет-источник средств
    # Может быть NULL для операций типа DEPOSIT (пополнение)
    source_account_id = Column(Integer, ForeignKey("accounts.account_id"), nullable=True)
    
    # dest_account_id - счет-получатель средств
    # Может быть NULL для операций типа WITHDRAWAL (снятие)
    dest_account_id = Column(Integer, ForeignKey("accounts.account_id"), nullable=True)
    
    # amount - сумма транзакции (всегда положительная)
    amount = Column(Float, nullable=False)
    
    currency = Column(String, default="USD")
    
    # type - тип транзакции из нашего Enum
    type = Column(SQLEnum(TransactionType), nullable=False)
    
    # status - текущий статус транзакции
    status = Column(SQLEnum(TransactionStatus), default=TransactionStatus.PENDING)
    
    # description - описание транзакции (например, "Оплата за кофе")
    description = Column(String)
    
    # created_at с индексом для быстрого поиска по дате
    # Это важно для отчетов и фильтрации
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # ===== ИНДЕКСЫ ДЛЯ ОПТИМИЗАЦИИ =====
    # __table_args__ позволяет задать дополнительные параметры таблицы
    # Составной индекс ускоряет поиск транзакций по счету и статусу
    __table_args__ = (
        ('source_account_id', 'dest_account_id', 'status'),  # Создает составной индекс
    )


class PaymentMethod(Base):
    """
    МОДЕЛЬ МЕТОДА ОПЛАТЫ
    Хранит информацию о способах оплаты пользователя
    (банковские карты, электронные кошельки и т.д.)
    """
    __tablename__ = "payment_methods"
    
    method_id = Column(Integer, primary_key=True, index=True)
    
    # user_id - какой пользователь владеет этим методом оплаты
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    
    # method_type - тип метода: "card", "wallet", "bank_transfer"
    method_type = Column(String)
    
    # masked_data - маскированные данные для безопасности
    # Например: "**** **** **** 1234" для карты
    masked_data = Column(String)
    
    # is_default - метод оплаты по умолчанию для пользователя
    is_default = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Связь с пользователем
    user = relationship("User", back_populates="payment_methods")


class AuditLog(Base):
    """
    МОДЕЛЬ ЛОГА АУДИТА
    Записывает все значимые действия в системе для отслеживания и безопасности.
    Критически важна для соответствия стандартам (PCI DSS, GDPR и т.д.)
    """
    __tablename__ = "audit_logs"
    
    log_id = Column(Integer, primary_key=True, index=True)
    
    # user_id может быть NULL для системных действий
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    
    # action - что произошло: "LOGIN", "TRANSFER", "CREATE_ACCOUNT" и т.д.
    action = Column(String, nullable=False)
    
    # resource_type - тип объекта: "User", "Account", "Transaction"
    resource_type = Column(String)
    
    # resource_id - ID объекта (в виде строки)
    resource_id = Column(String)
    
    # details - детали действия в формате JSON
    # Например: {"amount": 100, "from_account": 1, "to_account": 2}
    details = Column(String)
    
    # ip_address - IP адрес, с которого выполнено действие
    ip_address = Column(String)
    
    # timestamp с индексом для поиска по времени
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Связь с пользователем
    user = relationship("User", back_populates="audit_logs")


# ==================== PYDANTIC СХЕМЫ ====================
# Схемы Pydantic используются для:
# 1. Валидации входных данных (что пришло от клиента)
# 2. Сериализации выходных данных (что отправляем клиенту)
# 3. Документации API (автоматически генерируется документация)

class UserCreate(BaseModel):
    """
    СХЕМА ДЛЯ СОЗДАНИЯ ПОЛЬЗОВАТЕЛЯ
    Используется при регистрации нового пользователя.
    """
    # username: строка от 3 до 50 символов
    # Field(..., ...) - настройки поля
    # ... означает "обязательное поле"
    # min_length=3 - минимальная длина
    # max_length=50 - максимальная длина
    username: str = Field(..., min_length=3, max_length=50)
    
    # EmailStr - автоматически проверяет формат email
    email: EmailStr
    
    # Пароль минимум 8 символов
    password: str = Field(..., min_length=8)
    
    # full_name может быть не указан
    full_name: Optional[str] = None
    
    # ===== КАСТОМНАЯ ВАЛИДАЦИЯ =====
    # @validator - декоратор для создания функции-валидатора
    # 'password' - название поля, которое валидируем
    @validator('password')
    def validate_password(cls, v):
        """
        Проверяет сложность пароля.
        cls - ссылка на класс (UserCreate)
        v - значение поля (пароль)
        """
        # Проверка: есть ли хотя бы одна цифра
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        
        # Проверка: есть ли хотя бы одна заглавная буква
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        return v  # Возвращаем проверенное значение


class UserResponse(BaseModel):
    """
    СХЕМА ОТВЕТА С ДАННЫМИ ПОЛЬЗОВАТЕЛЯ
    Используется для отправки данных пользователя клиенту.
    Важно: НЕ содержит пароль!
    """
    user_id: int
    username: str
    email: str
    full_name: Optional[str]
    created_at: datetime
    
    class Config:
        """
        Конфигурация схемы Pydantic.
        from_attributes = True позволяет создавать объект схемы 
        из SQLAlchemy модели (например, User).
        Раньше это называлось orm_mode = True.
        """
        from_attributes = True


class AccountCreate(BaseModel):
    """Схема для создания нового счета"""
    account_type: AccountType = AccountType.CHECKING  # Значение по умолчанию
    currency: str = "USD"  # По умолчанию доллары


class AccountResponse(BaseModel):
    """Схема ответа с данными счета"""
    account_id: int
    account_type: AccountType
    balance: float
    currency: str
    status: AccountStatus
    created_at: datetime
    
    class Config:
        from_attributes = True


class TransactionCreate(BaseModel):
    """Схема для создания транзакции"""
    # Для переводов оба поля обязательны, для депозитов/выводов - один может быть NULL
    source_account_id: Optional[int] = None
    dest_account_id: Optional[int] = None
    
    # amount: положительное число больше 0
    # gt=0 означает "greater than 0" (больше 0)
    amount: float = Field(..., gt=0)
    
    currency: str = "USD"
    type: TransactionType
    description: Optional[str] = None


class TransactionResponse(BaseModel):
    """Схема ответа с данными транзакции"""
    transaction_id: int
    source_account_id: Optional[int]
    dest_account_id: Optional[int]
    amount: float
    currency: str
    type: TransactionType
    status: TransactionStatus
    created_at: datetime
    
    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    """Схема для запроса входа в систему"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Схема ответа с JWT токеном"""
    access_token: str
    token_type: str = "bearer"  # Всегда "bearer" для JWT
    expires_in: int  # Время жизни в секундах


class AnalyticsResponse(BaseModel):
    """Схема ответа с аналитикой"""
    total_transactions: int      # Сколько всего транзакций
    total_volume: float          # Общая сумма всех транзакций
    average_transaction: float   # Средняя сумма транзакции
    success_rate: float          # Процент успешных транзакций
    period: str                  # За какой период (например, "Last 30 days")


# ==================== ФУНКЦИИ БЕЗОПАСНОСТИ ====================

def get_password_hash(password: str) -> str:
    """
    ХЕШИРОВАНИЕ ПАРОЛЯ
    Преобразует обычный пароль в безопасный хеш.
    Хеш - это "отпечаток" пароля, но нельзя восстановить пароль из хеша.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    ПРОВЕРКА ПАРОЛЯ
    Сравнивает введенный пароль с хешем из базы данных.
    Возвращает True если пароль верный, False если нет.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    СОЗДАНИЕ JWT ТОКЕНА
    JWT (JSON Web Token) - стандарт для аутентификации.
    Токен содержит данные о пользователе и подписан секретным ключом.
    """
    # Копируем данные, чтобы не изменять оригинальный словарь
    to_encode = data.copy()
    
    # Устанавливаем время истечения токена
    if expires_delta:
        # Если передано время жизни - используем его
        expire = datetime.utcnow() + expires_delta
    else:
        # По умолчанию - 15 минут
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    # Добавляем поле "exp" (expiration time) в данные токена
    # JWT библиотека автоматически проверит это поле
    to_encode.update({"exp": expire})
    
    # Кодируем данные в JWT токен
    # jwt.encode() создает токен из данных, подписывая его SECRET_KEY
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def verify_token(token: str) -> dict:
    """
    ВЕРИФИКАЦИЯ JWT ТОКЕНА
    Проверяет подпись токена и извлекает данные из него.
    """
    try:
        # jwt.decode() проверяет подпись и извлекает данные
        # Если токен невалидный (поддельный, истекший) - выбросит исключение
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.InvalidTokenError:
        # Если токен невалидный - выбрасываем HTTP исключение
        raise HTTPException(status_code=401, detail="Invalid token")


# ==================== КЛАССЫ-ВАЛИДАТОРЫ ====================
# Валидаторы содержат бизнес-правила проверки данных

class PaymentValidator:
    """
    ВАЛИДАТОР ПЛАТЕЖЕЙ
    Проверяет корректность платежных операций.
    Все методы статические - не требуют создания экземпляра класса.
    """
    
    @staticmethod
    def validate_amount(amount: float) -> bool:
        """
        ПРОВЕРКА СУММЫ
        - Должна быть больше 0 (нельзя переводить отрицательные суммы)
        - Не должна превышать лимит (1,000,000 для безопасности)
        """
        return amount > 0 and amount <= 1_000_000

    @staticmethod
    def validate_account_exists(db: Session, account_id: int) -> bool:
        """
        ПРОВЕРКА СУЩЕСТВОВАНИЯ СЧЕТА
        db: Session - сессия базы данных для выполнения запроса
        account_id: int - ID счета для проверки
        Возвращает True если счет существует
        """
        # Выполняем SQL запрос через SQLAlchemy
        # filter() - условие WHERE в SQL
        # first() - берет первую найденную запись или None если нет записей
        return db.query(Account).filter(Account.account_id == account_id).first() is not None

    @staticmethod
    def validate_sufficient_balance(db: Session, account_id: int, amount: float) -> bool:
        """
        ПРОВЕРКА ДОСТАТОЧНОСТИ СРЕДСТВ
        Проверяет, что на счете достаточно денег для операции.
        """
        # Находим счет по ID
        account = db.query(Account).filter(Account.account_id == account_id).first()
        
        # Проверяем что счет существует И баланс >= требуемой суммы
        return account and account.balance >= amount

    @staticmethod
    def validate_account_active(db: Session, account_id: int) -> bool:
        """
        ПРОВЕРКА АКТИВНОСТИ СЧЕТА
        Счет должен быть в статусе ACTIVE для операций.
        """
        account = db.query(Account).filter(Account.account_id == account_id).first()
        return account and account.status == AccountStatus.ACTIVE


class TransactionValidator:
    """
    ВАЛИДАТОР ТРАНЗАКЦИЙ
    Проверяет комплексные условия для транзакций.
    """
    
    @staticmethod
    def validate_transfer(db: Session, source_id: int, dest_id: int, amount: float) -> tuple[bool, str]:
        """
        КОМПЛЕКСНАЯ ВАЛИДАЦИЯ ПЕРЕВОДА
        Проверяет все условия для перевода денег.
        Возвращает кортеж: (успех_проверки, сообщение_об_ошибке)
        """
        # 1. Проверка активности счета-источника
        if not PaymentValidator.validate_account_active(db, source_id):
            return False, "Source account is not active"
        
        # 2. Проверка существования счета-получателя
        if not PaymentValidator.validate_account_exists(db, dest_id):
            return False, "Destination account does not exist"
        
        # 3. Проверка достаточности средств
        if not PaymentValidator.validate_sufficient_balance(db, source_id, amount):
            return False, "Insufficient balance"
        
        # 4. Проверка валидности суммы
        if not PaymentValidator.validate_amount(amount):
            return False, "Invalid amount"
        
        # 5. Проверка что перевод не на тот же счет
        if source_id == dest_id:
            return False, "Cannot transfer to same account"
        
        # Все проверки пройдены
        return True, "Valid"


# ==================== СЕРВИСЫ (БИЗНЕС-ЛОГИКА) ====================
# Сервисы содержат основную бизнес-логику приложения.
# Они НЕ знают о HTTP, API, вебе - только о бизнес-правилах.

class UserService:
    """
    СЕРВИС ПОЛЬЗОВАТЕЛЕЙ
    Управляет созданием и аутентификацией пользователей.
    """
    
    @staticmethod
    def create_user(db: Session, user: UserCreate) -> User:
        """
        СОЗДАНИЕ НОВОГО ПОЛЬЗОВАТЕЛЯ
        Принимает валидированные данные и создает запись в БД.
        """
        # 1. Проверяем не занят ли username
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            # Если пользователь с таким username уже есть - выбрасываем исключение
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # 2. Проверяем не занят ли email
        existing_email = db.query(User).filter(User.email == user.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # 3. Создаем объект пользователя для БД
        db_user = User(
            username=user.username,
            email=user.email,
            password_hash=get_password_hash(user.password),  # Хешируем пароль!
            full_name=user.full_name
        )
        
        # 4. Сохраняем в БД
        db.add(db_user)       # Добавляем объект в сессию
        db.commit()           # Сохраняем изменения в БД
        db.refresh(db_user)   # Обновляем объект из БД (получаем ID и т.д.)
        
        # 5. Логируем успешное создание
        logger.info(f"User created: {user.username}")
        
        return db_user

    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
        """
        АУТЕНТИФИКАЦИЯ ПОЛЬЗОВАТЕЛЯ
        Проверяет логин и пароль.
        Возвращает объект пользователя если все верно, иначе None.
        """
        # 1. Ищем пользователя по username
        user = db.query(User).filter(User.username == username).first()
        
        # 2. Если пользователь не найден ИЛИ пароль неверный
        if not user or not verify_password(password, user.password_hash):
            return None  # Аутентификация не удалась
        
        return user  # Аутентификация успешна


class AccountService:
    """
    СЕРВИС СЧЕТОВ
    Управляет созданием и управлением счетами.
    """
    
    @staticmethod
    def create_account(db: Session, user_id: int, account_data: AccountCreate) -> Account:
        """
        СОЗДАНИЕ НОВОГО СЧЕТА
        user_id: какой пользователь создает счет
        account_data: данные для создания счета
        """
        # Создаем объект счета
        account = Account(
            user_id=user_id,                     # Привязываем к пользователю
            account_type=account_data.account_type,
            currency=account_data.currency,
            balance=0.0  # Новый счет всегда с нулевым балансом
        )
        
        # Сохраняем в БД
        db.add(account)
        db.commit()
        db.refresh(account)
        
        # Логируем
        logger.info(f"Account created for user {user_id}")
        
        return account

    @staticmethod
    def get_user_accounts(db: Session, user_id: int) -> List[Account]:
        """
        ПОЛУЧЕНИЕ ВСЕХ СЧЕТОВ ПОЛЬЗОВАТЕЛЯ
        Возвращает список счетов принадлежащих пользователю.
        """
        # filter(Account.user_id == user_id) - WHERE user_id = {user_id}
        # all() - возвращает все найденные записи
        return db.query(Account).filter(Account.user_id == user_id).all()


class TransactionService:
    """
    СЕРВИС ТРАНЗАКЦИЙ
    О