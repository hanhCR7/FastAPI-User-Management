import uuid
import os
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from databases import get_db
from schemas import EmailRequest, EmailResponse, ActivationEmailRequest
from service.email_service import send_email

load_dotenv()
router = APIRouter(prefix="/api/email_service",tags=["emails"])
ACTIVATE_ACCOUNT_URL = os.getenv("ACTIVATE_ACCOUNT_URL")
@router.post("/send-email/", status_code=status.HTTP_200_OK)
async def send_email_api(email_request: EmailRequest, db: Session = Depends(get_db)):
    await send_email(db, email_request.recipient, email_request.subject, email_request.body)
    return {"message": "Email gửi thành công"}
# Gửi email xác thực tài khoản người dùng đã đăng ký
@router.post("/send-activation-email/", status_code=status.HTTP_200_OK)
async def send_activation_email_api(request: ActivationEmailRequest, db: Session = Depends(get_db)):
   """API gui email xac thuc tai khoan."""
   activation_link = f"{ACTIVATE_ACCOUNT_URL}?token={request.activation_token }"
   email_body = f"""
    <h2>Xác thực tài khoản</h2>
    <p>Nhấn vào link dưới đây để kích hoạt tài khoản của bạn:</p>
    <a href="{activation_link}">{activation_link}</a>
    """
   await send_email(db, request.recipient, "Xác thực tài khoản", email_body)
   return {
       "status": "success",
       "message": "Email gửi thành công"
    }