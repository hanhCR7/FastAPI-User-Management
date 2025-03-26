from datetime import datetime
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends
from dotenv import load_dotenv
import os
import httpx
USER_SERVICE_URL = 'http://localhost:9000/api/user_service/'
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/identity_service/login")
load_dotenv()
SERVICE_KEY = os.getenv('SERVICE_KEY')

def hash_password( password: str) -> str:
    return bcrypt_context.hash(password)
def verify_password( plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)
# Lấy thông tin user từ User Service
async def get_user(user_id: int):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f'{USER_SERVICE_URL}user/{user_id}')
            if response.status_code == 200:
                return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
# Xác thực user
async def get_user_with_password(username: str, password: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f'{USER_SERVICE_URL}authenticate',
                json={'username': username, 'password': password}
            )
            if response.status_code == 200:
                return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
# Cập nhật password
async def update_password(user_id: int, old_password: str, new_password_hash: str, token: str = Depends(oauth2_scheme)):
    headers = {"Authentication": f"Bearer {token}"}
    payload = {
        "old_password": old_password,
        "new_password": new_password_hash,
        "confirm_password": new_password_hash
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.put(
                f'{USER_SERVICE_URL}users/update-password/{user_id}', 
                headers=headers, 
                json=payload
            )
            if response.status_code == 200:
                return response.json()
        except httpx.RequestError as e:
            raise None
# Đăng ký user(lấy từ create_user của User Service)
async def sign_up_user(first_name: str, last_name: str, username: str, email: str, password_hash: str):
    headers = {"X-API-Key": SERVICE_KEY}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f'{USER_SERVICE_URL}user/create-user',
                headers=headers,
                json={
                    "first_name": first_name,
                    "last_name": last_name,
                    "username": username,
                    "email": email,
                    "password_hash": password_hash
                }
            )
            print("Response: ", response.text)
            if response.status_code == 201:
                return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
# Cập nhật last_login
async def update_last_login(user_id: int):
    headers = {"X-API-Key": SERVICE_KEY}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.put(
                f'{USER_SERVICE_URL}user/update_last_login/{user_id}',
                headers=headers,
                json={"last_login": datetime.utcnow().isoformat()}
            )
            if response.status_code == 200:
                return response.json()
            raise Exception(f"Request error: {response.text}")
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")
# Tạo log
async def log_user_action(user_id: int, action: str):
    headers = {"X-API-Key": SERVICE_KEY}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f'{USER_SERVICE_URL}create-log',
                headers=headers,
                params={"user_id": user_id, "action": action}
            )
            if response.status_code == 201:
                return response.json()
            raise Exception(f"Request error: {response.text}")
        except httpx.RequestError as e:
            raise Exception(f"Request error: {str(e)}")