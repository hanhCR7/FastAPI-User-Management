from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from databases import get_db
from schemas import EmailRequest, EmailResponse
from service.email_service import send_email


router = APIRouter(prefix="/api/email_service",tags=["emails"])

@router.post("/send-email/", status_code=status.HTTP_200_OK)
async def send_email_api(email_request: EmailRequest, db: Session = Depends(get_db)):
    await send_email(db, email_request.recipient, email_request.subject, email_request.body)
    return {"message": "Email sent successfully"}
# Gửi email xác thực tài khoản người dùng đã đăng ký
@router.post("/send-activation-email/", status_code=status.HTTP_200_OK)
async def send_activation_email_api(user_id: int, email: str, db: Session = Depends(get_db)):
    activation_link = f"http://localhost:8000/api/identity_service/activate/{user_id}"
    subject = "Xác thực tài khoản"
    body = f"Chào mừng bạn đến với hệ thống của chúng tôi. Để kích hoạt tài khoản, vui lòng click vào link sau: {activation_link}"
    await send_email(db, email, subject, body)
    return {"message": "Activation email sent successfully"}