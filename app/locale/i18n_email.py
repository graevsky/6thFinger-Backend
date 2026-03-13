from __future__ import annotations

from typing import Tuple

SUPPORTED_LANGS = {"ru", "en"}

_EMAIL_TEMPLATES = {
    "ru": {
        "email_add": (
            "Подтверждение почты",
            "Код подтверждения: {code}\n\n"
            "Срок действия: {ttl} минут.\n"
            "Если это были не вы — просто игнорируйте письмо.",
        ),
        "email_remove": (
            "Удаление почты из аккаунта",
            "Код подтверждения удаления почты: {code}\n\n"
            "Срок действия: {ttl} минут.\n"
            "Если это были не вы — просто игнорируйте письмо.",
        ),
        "password_reset": (
            "Восстановление пароля",
            "Код восстановления: {code}\n\n"
            "Срок действия: {ttl} минут.\n"
            "Если это были не вы — просто игнорируйте письмо.",
        ),
    },
    "en": {
        "email_add": (
            "Email verification",
            "Your verification code: {code}\n\n"
            "Expires in: {ttl} minutes.\n"
            "If this wasn’t you, just ignore this email.",
        ),
        "email_remove": (
            "Remove email from account",
            "Your email removal code: {code}\n\n"
            "Expires in: {ttl} minutes.\n"
            "If this wasn’t you, just ignore this email.",
        ),
        "password_reset": (
            "Password reset",
            "Your password reset code: {code}\n\n"
            "Expires in: {ttl} minutes.\n"
            "If this wasn’t you, just ignore this email.",
        ),
    },
}


def normalize_lang(lang: str | None, default: str = "ru") -> str:
    if not lang:
        return default
    v = str(lang).strip().lower()
    return v if v in SUPPORTED_LANGS else default


def build_email(
    lang: str | None, purpose: str, code: str, ttl_min: int
) -> Tuple[str, str]:
    lng = normalize_lang(lang, default="ru")
    tpl = _EMAIL_TEMPLATES.get(lng, _EMAIL_TEMPLATES["ru"]).get(purpose)

    if not tpl:
        tpl = _EMAIL_TEMPLATES["ru"]["password_reset"]

    subject, body_tpl = tpl
    return subject, body_tpl.format(code=code, ttl=ttl_min)
