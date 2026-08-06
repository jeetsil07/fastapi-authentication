from fastapi import FastAPI,HTTPException,Depends,Header
from jose import ExpiredSignatureError, JWTError, jwt
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from passlib.context import CryptContext

app = FastAPI()

#jwt configuration
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Oauth setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login2")

# Dummy user database
dummy_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("password")
    }
}

# create token
def create_token(data:dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# OAuth
#Hash Password
def hash_password(password:str):
    return pwd_context.hash(password)

# verify password
def verify_password(plain_password:str, hashed_password:str):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/login2")
def login2(form_data: OAuth2PasswordRequestForm = Depends()):
    user = dummy_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

# verify_token = oauth2_scheme
def verify_token2(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username = payload.get("sub")

        if username is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return username

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
# Protected Api
@app.get("/protected2")
def protected2(username: str = Depends(verify_token2)):
    return {
        "message": "This is a protected endpoint",
        "user": username
    }


# jwt
# Login Api(generate token)
@app.post("/login")
def login(username:str,password:str):
    if username == "admin" and password == "password":
        token = create_token({"sub": username})
        return {"access_token": token}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
# token verify
def verify_token(token:str = Header(None)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
# Protected Api
@app.get("/protected")
def protected(token: dict = Depends(verify_token)):
    return {"message": "This is a protected endpoint", "user": token["sub"]}