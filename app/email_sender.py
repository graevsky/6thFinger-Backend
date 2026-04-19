import os
import smtplib
import socket
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


class EmailNotConfigured(RuntimeError):
    """Raised when email sending is disabled or required SMTP settings are missing. Not used for now"""

    pass


class EmailDeliveryError(RuntimeError):
    pass


class IPv4SMTP(smtplib.SMTP):
    """SMTP client that connects using IPv4 only."""

    def _get_socket(self, host, port, timeout):
        last_exc = None
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)

        for family, socktype, proto, _, sockaddr in infos:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_exc = exc
                try:
                    sock.close()
                except Exception:
                    pass

        if last_exc:
            raise last_exc

        raise OSError(f"Could not connect to {host}:{port} over IPv4")


class SmtpEmailSender:
    """Simple SMTP sender used for verification and recovery emails."""

    def __init__(self) -> None:
        self.host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("GMAIL_USER")
        self.password = (os.getenv("GMAIL_APP_PASSWORD") or "").replace(" ", "")
        self.from_email = os.getenv("EMAIL_FROM") or self.user
        self.enabled = os.getenv("EMAIL_ENABLED", "true").lower() == "true"

    def ensure_ready(self) -> None:
        """Validate that email sending is enabled and SMTP credentials are present."""
        if not self.enabled:
            raise EmailNotConfigured("Email sending disabled (EMAIL_ENABLED=false)")
        if not self.user or not self.password or not self.from_email:
            raise EmailNotConfigured(
                "Email not configured. Set GMAIL_USER, GMAIL_APP_PASSWORD (and optionally EMAIL_FROM)."
            )

    def send_text(self, to_email: str, subject: str, body: str) -> None:
        """Send a plain-text email via SMTP with STARTTLS."""
        self.ensure_ready()

        msg = EmailMessage()
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        try:
            with IPv4SMTP(self.host, self.port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.user, self.password)
                smtp.send_message(msg)
        except (OSError, smtplib.SMTPException) as exc:
            raise EmailDeliveryError(f"SMTP delivery failed: {exc}") from exc
