from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from databases import get_db
from service.email_service import send_email
from schemas import EmailRequest, EmailResponse
from service.otp_service import generate_otp, validate_otp

router = APIRouter(prefix="/api/email_service",tags=["emails"])
@router.post("/send-otp-email/", status_code=status.HTTP_200_OK)
async def send_otp_email(user_id: int, email: str, db: Session = Depends(get_db)):
    try:
        otp = generate_otp(user_id, db)
        await send_email(email, "OTP Code", f"Your OTP code is: {otp}")
        return {"message": "OTP email sent successfully"}
    except Exception as e:
        return {"message": "Failed to send OTP email"}
@router.post("/validate-otp/", status_code=status.HTTP_200_OK)
async def validate_otp_api(user_id: int, otp: str, db: Session = Depends(get_db)):
    is_valid = await validate_otp(user_id, otp, db)
    if is_valid:
        return {"message": "OTP code is valid"}
    return {"message": "OTP code is invalid"}