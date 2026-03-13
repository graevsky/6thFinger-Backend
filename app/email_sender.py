import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


class EmailNotConfigured(RuntimeError):
    pass


class SmtpEmailSender:
    def __init__(self) -> None:
        self.host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("GMAIL_USER")
        self.password = (os.getenv("GMAIL_APP_PASSWORD") or "").replace(" ", "")
        self.from_email = os.getenv("EMAIL_FROM") or self.user
        self.enabled = os.getenv("EMAIL_ENABLED", "true").lower() == "true"

    def _ensure_ready(self) -> None:
        if not self.enabled:
            raise EmailNotConfigured("Email sending disabled (EMAIL_ENABLED=false)")
        if not self.user or not self.password or not self.from_email:
            raise EmailNotConfigured(
                "Email not configured. Set GMAIL_USER, GMAIL_APP_PASSWORD (and optionally EMAIL_FROM)."
            )

    def send_text(self, to_email: str, subject: str, body: str) -> None:
        self._ensure_ready()

        msg = EmailMessage()
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(self.host, self.port, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(self.user, self.password)
            smtp.send_message(msg)
