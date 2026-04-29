import os
from html import escape
import resend
from dotenv import load_dotenv

load_dotenv()


class EmailNotConfigured(RuntimeError):
    """Raised when email sending is disabled or required SMTP settings are missing. Not used for now"""

    pass


class EmailDeliveryError(RuntimeError):
    pass


class SmtpEmailSender:
    """Simple SMTP sender used for verification and recovery emails."""

    def __init__(self) -> None:
        self.enabled = os.getenv("EMAIL_ENABLED", "true").lower() == "true"
        self.api_key = os.getenv("RESEND_API_KEY")
        self.from_email = os.getenv("EMAIL_FROM", "")

    def ensure_ready(self) -> None:
        """Validate that email sending is enabled and Resend settings are present."""
        if not self.enabled:
            raise EmailNotConfigured("Email sending disabled (EMAIL_ENABLED=false)")

        if not self.api_key:
            raise EmailNotConfigured("Email not configured. Set RESEND_API_KEY.")

        if not self.from_email:
            raise EmailNotConfigured("Email not configured. Set EMAIL_FROM.")

    def send_text(self, to_email: str, subject: str, body: str) -> None:
        """Send a plain-text email via Resend."""
        self.ensure_ready()

        resend.api_key = self.api_key

        html_body = f"""
            <div style="font-family: Arial, sans-serif; line-height: 1.5;">
                <pre style="white-space: pre-wrap; font-family: Arial, sans-serif;">{escape(body)}</pre>
            </div>
            """

        try:
            resend.Emails.send(
                {
                    "from": self.from_email,
                    "to": [to_email],
                    "subject": subject,
                    "text": body,
                    "html": html_body,
                }
            )
        except Exception as exc:
            raise EmailDeliveryError(f"Resend delivery failed: {exc}") from exc
