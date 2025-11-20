import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Product, Order, ClickLog, OrderItem

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
TOKEN_EXPIRE_MIN = int(os.getenv("TOKEN_EXPIRE_MIN", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer(auto_error=False)

app = FastAPI(title="Pride Fashion API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory rate limiting for login (per-IP)
RATE_LIMIT_WINDOW_SEC = 60 * 15  # 15 minutes
RATE_LIMIT_MAX_ATTEMPTS = 20
rate_store: Dict[str, List[float]] = {}


def check_rate_limit(ip: str):
    now = datetime.now().timestamp()
    bucket = rate_store.get(ip, [])
    # drop old timestamps
    bucket = [t for t in bucket if now - t <= RATE_LIMIT_WINDOW_SEC]
    if len(bucket) >= RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    bucket.append(now)
    rate_store[ip] = bucket


# Utilities
class TokenData(BaseModel):
    user_id: str
    role: str


def create_access_token(data: dict, expires_minutes: int = TOKEN_EXPIRE_MIN):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme)) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # fetch user from DB
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["_id"] = str(user["_id"])
    return user


async def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# Health checks
@app.get("/")
def root():
    return {"message": "Pride Fashion API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:100]}"
    return response


# Auth models
class RegisterPayload(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/register")
def register(payload: RegisterPayload):
    # check existing
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="customer",
    )
    user_id = create_document("user", user)
    token = create_access_token({"sub": user_id, "role": "customer"})
    return {"token": token, "user": {"_id": user_id, "name": user.name, "email": user.email, "role": user.role}}


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request):
    # Rate limit per IP
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)

    doc = db["user"].find_one({"email": payload.email})
    if not doc or not verify_password(payload.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(doc["_id"]), "role": doc.get("role", "customer")})
    doc["_id"] = str(doc["_id"])
    return {"token": token, "user": {"_id": doc["_id"], "name": doc.get("name"), "email": doc.get("email"), "role": doc.get("role")}}


# Products
class ProductPayload(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    image: Optional[str] = None
    category: Optional[str] = None
    type: str = "owned"  # owned | affiliate
    affiliate_link: Optional[str] = None
    tracking_code: Optional[str] = None
    stock: Optional[int] = 0


@app.get("/api/products")
def list_products(q: Optional[str] = None, category: Optional[str] = None, type: Optional[str] = None, min_price: Optional[float] = None, max_price: Optional[float] = None):
    filter_q = {}
    if q:
        filter_q["title"] = {"$regex": q, "$options": "i"}
    if category:
        filter_q["category"] = category
    if type:
        filter_q["type"] = type
    if min_price is not None or max_price is not None:
        price_filter = {}
        if min_price is not None:
            price_filter["$gte"] = float(min_price)
        if max_price is not None:
            price_filter["$lte"] = float(max_price)
        filter_q["price"] = price_filter
    items = get_documents("product", filter_q)
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


@app.get("/api/products/{product_id}")
def get_product(product_id: str):
    try:
        doc = db["product"].find_one({"_id": ObjectId(product_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["_id"] = str(doc["_id"])
    return doc


@app.post("/api/products", dependencies=[Depends(require_admin)])
def create_product(payload: ProductPayload):
    prod = Product(**payload.model_dump())
    prod_id = create_document("product", prod)
    return {"_id": prod_id}


@app.put("/api/products/{product_id}", dependencies=[Depends(require_admin)])
def update_product(product_id: str, payload: ProductPayload):
    try:
        oid = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    update_doc = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["product"].update_one({"_id": oid}, {"$set": update_doc, "$currentDate": {"updated_at": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"updated": True}


@app.delete("/api/products/{product_id}", dependencies=[Depends(require_admin)])
def delete_product(product_id: str):
    try:
        oid = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    res = db["product"].delete_one({"_id": oid})
    return {"deleted": res.deleted_count == 1}


# Affiliate
class AffiliateClickResponse(BaseModel):
    redirect: str


@app.post("/api/affiliate/click/{product_id}")
def affiliate_click(product_id: str, request: Request):
    try:
        doc = db["product"].find_one({"_id": ObjectId(product_id), "type": "affiliate"})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    click = ClickLog(
        product_id=str(doc["_id"]),
        tracking_code=doc.get("tracking_code"),
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
        timestamp=datetime.now(timezone.utc),
    )
    create_document("clicklog", click)
    return {"redirect": doc.get("affiliate_link")}


# Orders
class CartItem(BaseModel):
    product_id: str
    quantity: int


class CreateOrderPayload(BaseModel):
    items: List[CartItem]


@app.post("/api/orders", dependencies=[Depends(get_current_user)])
def create_order(payload: CreateOrderPayload, user: dict = Depends(get_current_user)):
    if not payload.items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    # Build order with current prices
    order_items: List[OrderItem] = []
    total = 0.0
    for item in payload.items:
        try:
            prod = db["product"].find_one({"_id": ObjectId(item.product_id), "type": "owned"})
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid product id")
        if not prod:
            raise HTTPException(status_code=400, detail="Product not available")
        qty = max(1, int(item.quantity))
        price = float(prod.get("price", 0))
        total += price * qty
        order_items.append(OrderItem(product_id=str(prod["_id"]), quantity=qty, price=price))
    order = Order(user_id=str(user["_id"]), items=order_items, total=round(total, 2), status="pending", created_at=datetime.now(timezone.utc))
    order_id = create_document("order", order)
    return {"_id": order_id, "total": round(total, 2)}


@app.get("/api/orders", dependencies=[Depends(require_admin)])
def list_orders():
    orders = get_documents("order")
    for o in orders:
        o["_id"] = str(o["_id"])  # type: ignore
    return orders


# Users (admin)
@app.get("/api/auth/users", dependencies=[Depends(require_admin)])
def list_users():
    users = get_documents("user")
    for u in users:
        u["_id"] = str(u["_id"])  # type: ignore
        u.pop("password_hash", None)
    return users


# Seed 100 users
@app.post("/api/auth/seed")
def seed_users():
    from faker import Faker
    fake = Faker()
    created = 0
    # Ensure one admin
    if not db["user"].find_one({"role": "admin"}):
        admin = User(name="Admin", email="admin@pridefashion.io", password_hash=hash_password("Admin@123"), role="admin")
        create_document("user", admin)
        created += 1
    # Create 100 customers if not present
    existing_count = db["user"].count_documents({"role": "customer"})
    to_create = max(0, 100 - existing_count)
    for _ in range(to_create):
        name = fake.name()
        email = fake.unique.email()
        pwd = hash_password("Password@123")
        user = User(name=name, email=email, password_hash=pwd, role="customer")
        create_document("user", user)
        created += 1
    return {"created": created}


# Simple wishlist: store per-user list in collection
class WishlistPayload(BaseModel):
    product_id: str


@app.get("/api/wishlist", dependencies=[Depends(get_current_user)])
def get_wishlist(user: dict = Depends(get_current_user)):
    docs = get_documents("wishlist", {"user_id": str(user["_id"])})
    for d in docs:
        d["_id"] = str(d["_id"])  # type: ignore
    return docs


@app.post("/api/wishlist", dependencies=[Depends(get_current_user)])
def add_wishlist(payload: WishlistPayload, user: dict = Depends(get_current_user)):
    # prevent duplicates
    exists = db["wishlist"].find_one({"user_id": str(user["_id"]), "product_id": payload.product_id})
    if exists:
        return {"added": False}
    wid = db["wishlist"].insert_one({
        "user_id": str(user["_id"]),
        "product_id": payload.product_id,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }).inserted_id
    return {"added": True, "_id": str(wid)}


@app.delete("/api/wishlist/{wish_id}", dependencies=[Depends(get_current_user)])
def remove_wishlist(wish_id: str, user: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(wish_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    res = db["wishlist"].delete_one({"_id": oid, "user_id": str(user["_id"])})
    return {"deleted": res.deleted_count == 1}


# Public Home content for frontend
@app.get("/api/home")
def home_content():
    hero = {
        "title": "Pride Fashion",
        "subtitle": "Bold. Modern. You.",
        "cta": "Shop Now",
        "image": "https://images.unsplash.com/photo-1512436991641-6745cdb1723f?w=1600&q=80&auto=format&fit=crop"
    }
    trending = list_products(type=None)[:8]
    return {"hero": hero, "trending": trending}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
