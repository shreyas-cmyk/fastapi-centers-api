from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
import datetime
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Centers API", description="Search centers by company name, center name, or unique key.", version="1.0")

DB_CONFIG = {
    "dbname": "YOUR_DBNAME",
    "user": "YOUR_DBUSER",
    "password": "YOUR_DBPASSWORD",
    "host": "YOUR_DBHOST",
    "port": "5432"
}

SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(email: str):
    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cur.fetchone()

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(email)
    if user is None:
        raise credentials_exception
    return user

@app.post("/register")
async def register(email: str = Query(...), password: str = Query(...)):
    hashed_password = get_password_hash(password)
    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            cur.execute("INSERT INTO users (email, password) VALUES (%s, %s) RETURNING *",
                        (email, hashed_password))
            conn.commit()
            return {"message": "User created successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/centers")
async def get_centers(
    company_name: Optional[str] = Query(None, description="Company (account_global_legal_name) to search"),
    center_name: Optional[str] = Query(None, description="Center name to search"),
    unique_key: Optional[str] = Query(None, description="Unique key to search"),
    fuzzy: Optional[bool] = Query(False, description="Use fuzzy ILIKE search"),
    current_user: dict = Depends(get_current_user)
):
    if not company_name and not center_name and not unique_key:
        raise HTTPException(status_code=400, detail="Provide at least one search parameter")

    query = "SELECT * FROM centers1 WHERE 1=1"
    params = []

    if company_name:
        if fuzzy:
            query += " AND account_global_legal_name ILIKE %s"
            params.append(f"%{company_name}%")
        else:
            query += " AND account_global_legal_name = %s"
            params.append(company_name)

    if center_name:
        if fuzzy:
            query += " AND center_legal_name_cd ILIKE %s"
            params.append(f"%{center_name}%")
        else:
            query += " AND center_legal_name_cd = %s"
            params.append(center_name)

    if unique_key:
        if fuzzy:
            query += " AND (punique_key ILIKE %s OR cn_unique_key_cd ILIKE %s)"
            params.append(f"%{unique_key}%")
            params.append(f"%{unique_key}%")
        else:
            query += " AND (punique_key = %s OR cn_unique_key_cd = %s)"
            params.append(unique_key)
            params.append(unique_key)

    with psycopg2.connect(**DB_CONFIG) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            results = cur.fetchall()

    return {"count": len(results), "results": results}
