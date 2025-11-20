"""
Database Schemas for Pride Fashion

Each Pydantic model represents a MongoDB collection. Collection name is the lowercase of the class name.
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Users collection
class User(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password_hash: str = Field(..., min_length=10)
    role: Literal["admin", "customer"] = "customer"
    is_active: bool = True

# Products collection (owned and affiliate)
class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    image: Optional[str] = None
    category: Optional[str] = None
    type: Literal["owned", "affiliate"] = "owned"
    affiliate_link: Optional[str] = None
    tracking_code: Optional[str] = None
    stock: Optional[int] = Field(default=0, ge=0)

# Orders collection
class OrderItem(BaseModel):
    product_id: str
    quantity: int = Field(..., ge=1)
    price: float = Field(..., ge=0)

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    total: float = Field(..., ge=0)
    status: Literal["pending", "paid", "shipped", "completed", "cancelled"] = "pending"
    created_at: Optional[datetime] = None

# Click logs for affiliate tracking
class ClickLog(BaseModel):
    product_id: str
    tracking_code: Optional[str] = None
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
