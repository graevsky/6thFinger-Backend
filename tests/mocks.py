class FakeEmailSender:
    def __init__(self):
        self.sent = []

    def ensure_ready(self):
        return None

    def send_text(self, email: str, subject: str, text: str):
        self.sent.append(
            {
                "email": email,
                "subject": subject,
                "text": text,
            }
        )
