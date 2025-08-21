import os

from fastapi import FastAPI, Depends, HTTPException, status, Request,Query
from fastavro.schema import fullname
import requests
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .database.db import Base,engine,get_db,SessionLocal
from .database import models as models
from .database import schema as schema
from .auth.validate_user import get_current_user
from .auth.auth import hash_password,verify_password,create_access_token
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Zentry Backend")

# Add CORS middleware
origins = [
    "*",  # allow all origins for testing; in production, list allowed domains
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,        # or ["https://yourfrontend.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.security import OAuth2PasswordRequestForm
class LoginRequest(BaseModel):
    email: str
    password: str
class BusinessCreate(BaseModel):
    name: str
    industry: str
#create tables
Base.metadata.create_all(bind=engine)
app = FastAPI(title="Zentry Backend")
@app.get("/")
def root():
    return {"message": "CRM API is running 🚀"}

#register user
@app.post("/register", response_model=schema.UserOut)
def register(user: schema.UserCreate, db: Session = Depends(get_db)):
    # check if user exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    #create new user
    new_user= models.User(email= user.email, hashed_password= hash_password(user.password), full_name= user.full_name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

#login
@app.post("/login", response_model=schema.Token)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()

    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")

def read_me(current_user: models.User = Depends(get_current_user)):
    return {"email": current_user.email, "full_name": current_user.full_name}


@app.post("/users/{user_id}/add-business")
def add_business(user_id: int, business_in: BusinessCreate, db: Session = Depends(get_db)):
    # fetch the user
    user = db.query(models.User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # create the business
    new_business = models.Business(
        name=business_in.name,
        industry=business_in.industry,
        owner_id=user.id
    )
    db.add(new_business)
    db.commit()
    db.refresh(new_business)

    return {
        "message": f"Business '{new_business.name}' added for user '{user.email}'",
        "business": {"id": new_business.id, "name": new_business.name, "industry": new_business.industry}
    }
@app.get("/privacy-policy")
def privacy_policy():
    return {
        "title": "Privacy Policy - Zentry CRM",
        "last_updated": "2025-08-21",
        "content": """
        Zentry CRM respects your privacy. This Privacy Policy explains how we collect, use, 
        and protect your information when you use our CRM services and connect your Instagram account.

        1. Information We Collect:
           - Account details (email, name) when you register.
           - Business information you provide (business name, industry, etc.).
           - Instagram data (access tokens, business account IDs) when you connect Instagram.
           - CRM usage data (interactions, leads, and customer messages).

        2. How We Use Your Information:
           - To provide CRM features such as lead management, business tracking, 
             and Instagram message integration.
           - To authenticate your account and secure access.
           - To improve our services and provide support.

        3. Sharing of Information:
           - We do not sell or rent your data.
           - We may share data only with trusted third parties necessary for 
             Instagram API integration and payment processing.
           - We comply with all legal obligations if required to disclose information.

        4. Data Retention:
           - We store Instagram access tokens securely and refresh them as required.
           - You can disconnect Instagram at any time, which deletes your token.
           - We retain business data until you request deletion.

        5. Security:
           - Tokens and sensitive data are encrypted and stored securely.
           - We implement industry-standard security practices.

        6. Your Rights:
           - You can request access, correction, or deletion of your data at any time 
             by contacting support.

        7. Contact:
           If you have any questions, please contact us at: support@zentrycrm.com
        """
    }



#IG NEEDED=
APP_ID=os.getenv('IG_API_ID')
APP_SECRET=os.getenv('IG_APP_SECRET')
WEBHOOK_VERIFY_TOKEN= os.getenv('WEBHOOK_VERIFY_TOKEN')
REDIRECT_URI=os.getenv('REDIRECT_URL')

# --- Instagram Webhook ---
@app.get("/webhook/instagram")
def verify_webhook(
        hub_mode: str = Query(..., alias="hub.mode"),
        hub_verify_token: str = Query(..., alias="hub.verify_token"),
        hub_challenge: str = Query(..., alias="hub.challenge")
):
    # Verification GET request
    if hub_mode == "subscribe" and hub_verify_token == WEBHOOK_VERIFY_TOKEN:
        return JSONResponse(content=int(hub_challenge))
    return JSONResponse(content="Verification failed", status_code=403)


@app.post("/webhook/instagram")
async def instagram_webhook(request: Request):
    data = await request.json()
    # TODO: handle/save updates (comments, messages, etc.)
    print("Instagram webhook payload:", data)
    return {"status": "received"}


# --- Instagram OAuth callback to get access token ---
@app.get("/instagram/callback")
def instagram_callback(code: str, business_id: int, db: Session = Depends(get_db)):
    """
    Exchanges the code for long-lived access token and stores it in Business table
    business_id: which business to connect
    """
    # Step 1: Short-lived token
    r = requests.get("https://api.instagram.com/oauth/access_token", params={
        "client_id": APP_ID,
        "redirect_uri": REDIRECT_URI,
        "grant_type":"authorization_code",
        "client_secret": APP_SECRET,
        "code": code
    })
    r.raise_for_status()
    short_token = r.json()["access_token"]

    # Step 2: Long-lived token
    r2 = requests.get("https://api.instagram.com/oauth/access_token", params={
        "grant_type": "ig_exchange_token",
        "client_id": APP_ID,
        "client_secret": APP_SECRET,
        "access_token": short_token
    })
    r2.raise_for_status()
    long_token = r2.json()["access_token"]

    # Step 3: Get IG Business ID from page
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    # You must have a linked Facebook Page ID in the business
    page_id = business.page_id
    ig_account_info = requests.get(
        f"https://graph.instagram.com/{page_id}?fields=instagram_business_account&access_token={long_token}"
    ).json()
    ig_user_id = ig_account_info.get("instagram_business_account", {}).get("id")

    # Step 4: Save tokens in DB
    business.ig_user_id = ig_user_id
    business.access_token = long_token
    business.token_expires_at = datetime.utcnow() + timedelta(days=60)
    db.commit()
    db.refresh(business)

    return {"detail": "Instagram Business connected successfully", "ig_user_id": ig_user_id}
