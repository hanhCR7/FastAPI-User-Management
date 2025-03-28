import httpx
import asyncio
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="http://localhost:9001/api/identity_service/login")
URL = "http://localhost:9001/api/identity_service/"
async def validate_token_user(token: str = Depends(oauth2_scheme)):
    headers = {
        "Authorization": f"Bearer {token}",
    }
    async with httpx.AsyncClient(follow_redirects=True) as client:
        try:
            response = await client.get(
                f"{URL}validate-token",
                headers=headers,
            ) 
            if response.status_code != 200:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không tồn tại!!!")
            try:
                data = response.json()
            except ValueError:
                raise HTTPException(status_code=500, detail="Phản hồi JSON không hợp lệ từ dịch vụ xác thực mã thông báo!!!")
            return {
                "user_id": data["user_id"],
                "username": data["username"],
                "role": data["role"],
            }
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Lỗi khi tìm nạp người dùng: {str(e)}")

    