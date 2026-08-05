from fastapi import FastAPI,HTTPException,Depends,Header
from jose import jwt
from datetime import datetime, timedelta, timezone

app = FastAPI()
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

#create token
def create_token(data:dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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