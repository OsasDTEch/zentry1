import os

from fastapi import FastAPI, Depends, HTTPException, status, Request,Query
from fastavro.schema import fullname
import requests
from fastapi import Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import urllib.parse

from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from .database.db import Base,engine,get_db,SessionLocal
from .database import models as models
from .database import schema as schema
from fastapi import Query
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
APP_ID=os.getenv('IG_APP_ID')
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

# Update your existing callback to be simpler and work with existing columns
@app.get("/instagram/callback")
def instagram_callback(request: Request, db: Session = Depends(get_db)):
    """
    Handle Instagram Business Login callback
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        raise HTTPException(status_code=400, detail=f"Authorization failed: {error}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    # Extract business_id from state
    try:
        business_id = int(state.split("business_id=")[1])
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    try:
        # Step 1: Exchange code for short-lived token
        token_response = requests.post(
            "https://graph.instagram.com/oauth/access_token",
            data={
                "client_id": APP_ID,
                "client_secret": APP_SECRET,
                "redirect_uri": REDIRECT_URI,
                "code": code
            }
        )

        if token_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Token exchange failed: {token_response.text}"
            )

        token_data = token_response.json()
        short_token = token_data.get("access_token")
        user_id = token_data.get("user_id")

        if not short_token or not user_id:
            raise HTTPException(status_code=400, detail="Invalid token response")

        # Step 2: Exchange for long-lived token
        long_lived_response = requests.get(
            "https://graph.instagram.com/oauth/access_token",
            params={
                "grant_type": "fb_exchange_token",
                "client_id": APP_ID,
                "client_secret": APP_SECRET,
                "fb_exchange_token": short_token
            }
        )

        if long_lived_response.status_code == 200:
            long_lived_data = long_lived_response.json()
            access_token = long_lived_data.get("access_token", short_token)
            expires_in = long_lived_data.get("expires_in", 3600)
        else:
            access_token = short_token
            expires_in = 3600

        # Step 3: Get user profile
        profile_response = requests.get(
            f"https://graph.instagram.com/{user_id}",
            params={
                "fields": "id,username,name,account_type,media_count,followers_count",
                "access_token": access_token
            }
        )

        if profile_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Profile fetch failed: {profile_response.text}"
            )

        profile_data = profile_response.json()

        # Verify business account
        if profile_data.get("account_type") not in ["BUSINESS", "CREATOR"]:
            raise HTTPException(
                status_code=400,
                detail="Account must be Instagram Business or Creator account"
            )

        # Step 4: Save to database
        business.ig_user_id = user_id
        business.access_token = access_token
        business.page_id = None  # Not needed for Instagram-only login
        business.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

        db.commit()
        db.refresh(business)

        return {
            "success": True,
            "message": f"Instagram connected successfully for {business.name}",
            "business_id": business_id,
            "instagram_data": {
                "username": profile_data.get("username"),
                "account_type": profile_data.get("account_type"),
                "followers_count": profile_data.get("followers_count"),
                "media_count": profile_data.get("media_count")
            },
            "token_expires": business.token_expires_at.isoformat(),
            "available_features": [
                "Manage comments",
                "Send/receive direct messages",
                "Publish content",
                "Basic profile access"
            ]
        }

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"API request failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

# 2. Connection Status Check
@app.get("/business/{business_id}/instagram-status")
def get_instagram_status(business_id: int, db: Session = Depends(get_db)):
    """
    Check the current Instagram connection status
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    if not business.access_token or not business.ig_user_id:
        return {
            "connected": False,
            "message": "Instagram not connected",
            "business_name": business.name,
            "facebook_auth_url": f"/instagram/auth/{business_id}",
            "instagram_auth_url": f"/instagram/auth-instagram/{business_id}"
        }

    # Check if token is expired
    is_expired = (
            business.token_expires_at and
            business.token_expires_at < datetime.utcnow()
    )

    return {
        "connected": True,
        "business_name": business.name,
        "ig_user_id": business.ig_user_id,
        "page_id": business.page_id,
        "token_expired": is_expired,
        "expires_at": business.token_expires_at.isoformat() if business.token_expires_at else None,
        "needs_reconnection": is_expired,
        "reconnect_url": f"/instagram/auth/{business_id}" if is_expired else None
    }


# 3. Test Connection
# Also update your test endpoint to use graph.instagram.com
@app.get("/business/{business_id}/test-instagram")
def test_instagram_connection(business_id: int, db: Session = Depends(get_db)):
    """
    Test Instagram Business Login connection
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    if not business.access_token or not business.ig_user_id:
        raise HTTPException(status_code=400, detail="Instagram not connected")

    try:
        # Test API call using graph.instagram.com
        test_response = requests.get(
            f"https://graph.instagram.com/{business.ig_user_id}",
            params={
                "fields": "id,username,name,account_type,profile_picture_url,followers_count,media_count",
                "access_token": business.access_token
            }
        )

        if test_response.status_code != 200:
            return {
                "success": False,
                "error": f"API call failed: {test_response.text}",
                "suggestion": "Token may be expired or invalid"
            }

        profile_data = test_response.json()

        return {
            "success": True,
            "message": "Instagram Business Login connection working!",
            "profile": profile_data,
            "business_name": business.name,
            "api_host": "graph.instagram.com"
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Connection test failed: {str(e)}"
        }



@app.get("/instagram/auth/{business_id}")
def get_instagram_auth_url(business_id: int, db: Session = Depends(get_db)):
    """
    Generate Instagram Business Login authorization URL
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    # Correct scopes for Instagram Business Login
    scopes = [
        "instagram_basic",
        "instagram_manage_comments",
        "instagram_manage_messages",
        "instagram_content_publish"
    ]

    scope_string = ",".join(scopes)
    state = f"business_id={business_id}"

    auth_url = (
        f"https://www.instagram.com/oauth/authorize"
        f"?client_id={APP_ID}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        f"&scope={scope_string}"
        f"&response_type=code"
        f"&state={urllib.parse.quote(state)}"
    )

    return {
        "auth_url": auth_url,
        "business_id": business_id,
        "business_name": business.name,
        "login_type": "Instagram Business Login",
        "available_features": [
            "Basic profile access",
            "Manage comments",
            "Manage direct messages",
            "Content publishing"
        ],
        "note": "Click the auth_url to authorize Instagram access"
    }

