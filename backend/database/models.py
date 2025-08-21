from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, func, Enum
from sqlalchemy.orm import relationship, declarative_base
import enum

from zentry.backend.database.db import Base


# --- ENUMS ---
class LeadStatus(enum.Enum):
    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    LOST = "lost"
    WON = "won"


# --- MODELS ---

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # One user can own many businesses
    businesses = relationship("Business", back_populates="owner")


class Business(Base):
    __tablename__ = "businesses"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    industry = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ig_user_id = Column(String, nullable=True)        # Instagram User ID
    page_id = Column(String, nullable=True)           # Facebook Page ID
    access_token = Column(String, nullable=True)      # IG Graph API token
    token_expires_at = Column(DateTime(timezone=True), nullable=True) # optional
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="businesses")
    customers = relationship("Customer", back_populates="business")
    leads = relationship("Lead", back_populates="business")
    messages = relationship("Message", back_populates="business")
    appointments = relationship("Appointment", back_populates="business")


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer, ForeignKey("businesses.id"), nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, unique=False, nullable=True)
    phone = Column(String, unique=False, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    business = relationship("Business", back_populates="customers")
    leads = relationship("Lead", back_populates="customer")
    messages = relationship("Message", back_populates="customer")
    appointments = relationship("Appointment", back_populates="customer")


class Lead(Base):
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer, ForeignKey("businesses.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    status = Column(Enum(LeadStatus), default=LeadStatus.NEW, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    business = relationship("Business", back_populates="leads")
    customer = relationship("Customer", back_populates="leads")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer, ForeignKey("businesses.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    business = relationship("Business", back_populates="messages")
    customer = relationship("Customer", back_populates="messages")


class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    business_id = Column(Integer, ForeignKey("businesses.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    scheduled_time = Column(DateTime(timezone=True), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    business = relationship("Business", back_populates="appointments")
    customer = relationship("Customer", back_populates="appointments")
