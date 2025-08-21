import os

from fastapi import FastAPI, Depends, HTTPException, status, Request,Query
from fastavro.schema import fullname
import requests
from fastapi import Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

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
def instagram_callback(
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Simplified callback - works with existing database schema
    """
    # --- Step 0: Read query params ---
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")

    # Handle authorization errors
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"Authorization failed: {error} - {error_description or 'No description'}"
        )

    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")
    if not state:
        raise HTTPException(status_code=400, detail="State parameter missing")

    # --- Extract business_id ---
    try:
        if "business_id=" in state:
            business_id = int(state.split("business_id=")[1])
        else:
            business_id = int(state)
    except (ValueError, IndexError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid state format: {state}")

    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    try:
        # --- Step 1: Exchange code for short-lived token ---
        token_response = requests.post("https://graph.facebook.com/v18.0/oauth/access_token", data={
            "client_id": APP_ID,
            "client_secret": APP_SECRET,
            "redirect_uri": REDIRECT_URI,
            "code": code
        })

        if token_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Token exchange failed: {token_response.text}"
            )

        token_data = token_response.json()
        short_token = token_data.get("access_token")

        if not short_token:
            raise HTTPException(status_code=400, detail="No access token received")

        # --- Step 2: Exchange for long-lived token ---
        long_lived_response = requests.get("https://graph.facebook.com/v18.0/oauth/access_token", params={
            "grant_type": "fb_exchange_token",
            "client_id": APP_ID,
            "client_secret": APP_SECRET,
            "fb_exchange_token": short_token
        })

        if long_lived_response.status_code == 200:
            long_lived_data = long_lived_response.json()
            user_token = long_lived_data.get("access_token", short_token)
        else:
            user_token = short_token

        # --- Step 3: Get user's Facebook Pages ---
        pages_response = requests.get(
            "https://graph.facebook.com/v18.0/me/accounts",
            params={
                "access_token": user_token,
                "fields": "id,name,access_token,instagram_business_account"
            }
        )

        if pages_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch pages: {pages_response.text}"
            )

        pages_data = pages_response.json()
        pages = pages_data.get("data", [])

        if not pages:
            raise HTTPException(status_code=400, detail="No Facebook Pages found")

        # --- Step 4: Find page with Instagram Business Account ---
        instagram_page = None
        for page in pages:
            if page.get("instagram_business_account"):
                instagram_page = page
                break

        if not instagram_page:
            return {
                "status": "partial_success",
                "message": "Facebook connected but no Instagram Business Account found",
                "available_pages": [{"id": p["id"], "name": p["name"]} for p in pages],
                "instructions": "Please link an Instagram Business Account to one of your Facebook Pages"
            }

        # --- Step 5: Save to database (using existing columns only) ---
        business.ig_user_id = instagram_page["instagram_business_account"]["id"]
        business.access_token = instagram_page["access_token"]  # Use page token
        business.page_id = instagram_page["id"]
        business.token_expires_at = datetime.utcnow() + timedelta(days=60)

        db.commit()
        db.refresh(business)

        return {
            "success": True,
            "detail": f"Instagram successfully connected for {business.name}",
            "business_id": business_id,
            "business_name": business.name,
            "ig_user_id": business.ig_user_id,
            "page_id": business.page_id,
            "page_name": instagram_page.get("name"),
            "expires_at": business.token_expires_at.isoformat(),
            "next_steps": "You can now manage Instagram messages and comments through the CRM"
        }

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"API request failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")


@app.get("/instagram/auth-instagram/{business_id}")
def get_instagram_business_auth_url(business_id: int, db: Session = Depends(get_db)):
    """
    Generate Instagram Business Login authorization URL
    Use this if your Instagram account is NOT linked to a Facebook Page
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    # For Instagram Business Login (direct Instagram login)
    scopes = [
        "instagram_basic",
        "instagram_manage_comments",
        "instagram_manage_messages"
        # Note: pages_show_list not needed for direct Instagram login
    ]

    scope_string = ",".join(scopes)
    state = f"business_id={business_id}"

    auth_url = (
        f"https://www.instagram.com/oauth/authorize?"
        f"client_id={APP_ID}&"  # Use Instagram App ID here
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={scope_string}&"
        f"response_type=code&"
        f"state={state}"
    )

    return {
        "auth_url": auth_url,
        "business_id": business_id,
        "business_name": business.name,
        "required_permissions": scopes,
        "login_type": "Instagram Business Login",
        "instructions": "Click the auth_url to authorize Instagram access directly"
    }




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
@app.get("/business/{business_id}/test-instagram")
def test_instagram_connection(business_id: int, db: Session = Depends(get_db)):
    """
    Test the Instagram connection by making a simple API call
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    if not business.access_token or not business.ig_user_id:
        raise HTTPException(status_code=400, detail="Instagram not connected")

    try:
        # Test API call - get basic profile info
        test_response = requests.get(
            f"https://graph.facebook.com/v18.0/{business.ig_user_id}",
            params={
                "fields": "id,username,name,profile_picture_url,followers_count,media_count",
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
            "message": "Instagram connection working!",
            "profile": profile_data,
            "business_name": business.name
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Connection test failed: {str(e)}"
        }


# 4. Get Instagram Messages (for CRM functionality)
@app.get("/business/{business_id}/instagram-messages")
def get_instagram_messages(business_id: int, db: Session = Depends(get_db)):
    """
    Get recent Instagram messages for CRM
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    if not business.access_token or not business.ig_user_id:
        raise HTTPException(status_code=400, detail="Instagram not connected")

    try:
        # Get conversations
        conversations_response = requests.get(
            f"https://graph.facebook.com/v18.0/{business.ig_user_id}/conversations",
            params={
                "fields": "participants,updated_time,message_count",
                "access_token": business.access_token
            }
        )

        if conversations_response.status_code != 200:
            return {
                "success": False,
                "error": f"Failed to fetch conversations: {conversations_response.text}"
            }

        conversations_data = conversations_response.json()

        return {
            "success": True,
            "business_name": business.name,
            "conversations": conversations_data.get("data", []),
            "total_conversations": len(conversations_data.get("data", []))
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to fetch messages: {str(e)}"
        }


# 5. Disconnect Instagram
@app.delete("/business/{business_id}/disconnect-instagram")
def disconnect_instagram(business_id: int, db: Session = Depends(get_db)):
    """
    Disconnect Instagram account from business
    """
    business = db.query(models.Business).get(business_id)
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")

    if not business.ig_user_id:
        raise HTTPException(status_code=400, detail="Instagram not connected")

    # Clear Instagram data
    business.ig_user_id = None
    business.access_token = None
    business.page_id = None
    business.token_expires_at = None

    db.commit()

    return {
        "success": True,
        "message": f"Instagram disconnected from {business.name}",
        "business_id": business_id
    }