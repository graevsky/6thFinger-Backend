import os
from html import escape
import resend
from dotenv import load_dotenv

load_dotenv()


def is_email_enabled() -> bool:
    """Return whether email flows are globally enabled."""
    raw = os.getenv("EMAIL_ENABLED", "true")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class EmailDisabledError(RuntimeError):
    """Raised when email flows are disabled by configuration."""

    pass


class EmailNotConfigured(RuntimeError):
    """Raised when email sending is enabled but Resend settings are missing."""

    pass


class EmailDeliveryError(RuntimeError):
    pass


class SmtpEmailSender:
    """Simple Resend sender used for verification and recovery emails."""

    def __init__(self) -> None:
        self.enabled = is_email_enabled()
        self.api_key = os.getenv("RESEND_API_KEY")
        self.from_email = os.getenv("EMAIL_FROM", "")

    def ensure_ready(self) -> None:
        """Validate that email sending is enabled and Resend settings are present."""
        if not self.enabled:
            raise EmailDisabledError("Email sending disabled (EMAIL_ENABLED=false)")

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
