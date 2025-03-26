import smtplib
from email.mime.text import MIMEText
from sqlalchemy.orm import Session
from models import EmailLogs
import os
from dotenv import load_dotenv
load_dotenv()

SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_FROM = os.getenv("SMTP_FROM")
async def send_email(db: Session, recipient: str, subject: str, body: str):
    msg = MIMEText(body, "html")
    msg["From"] = SMTP_FROM
    msg["To"] = recipient
    msg["Subject"] = subject

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, recipient, msg.as_string())
        server.quit()


