from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from zentry.backend.database.db import get_db
import os

import zentry.backend.database.models as models
SECRET_KEY = os.getenv('AUTH_SECRET_KEY')
print(SECRET_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


ALGORITHM = "HS256"


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = db.query(models.User).get(int(user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user
