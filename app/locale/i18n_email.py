from __future__ import annotations

import os
from html import escape
from typing import Tuple

SUPPORTED_LANGS = {"ru", "en"}

_EMAIL_TEMPLATES = {
    "ru": {
        "greeting_named": "Добрый день, {username}!",
        "greeting_generic": "Добрый день!",
        "signoff": "С уважением,",
        "team": "команда Prothesis.ru",
        "landing_label": "На лендинг Prothesis.ru",
        "guide_label": "На гайд Руководство",
        "email_add": {
            "subject": "Подтверждение почты",
            "code_label": "Код подтверждения",
            "ttl_line": "Срок действия: {ttl} минут.",
            "ignore_line": "Если это были не вы — просто игнорируйте письмо.",
        },
        "email_remove": {
            "subject": "Удаление почты из аккаунта",
            "code_label": "Код подтверждения удаления почты",
            "ttl_line": "Срок действия: {ttl} минут.",
            "ignore_line": "Если это были не вы — просто игнорируйте письмо.",
        },
        "password_reset": {
            "subject": "Восстановление пароля",
            "code_label": "Код восстановления",
            "ttl_line": "Срок действия: {ttl} минут.",
            "ignore_line": "Если это были не вы — просто игнорируйте письмо.",
        },
    },
    "en": {
        "greeting_named": "Good day, {username}!",
        "greeting_generic": "Good day!",
        "signoff": "Best regards,",
        "team": "The Prothesis.ru team",
        "landing_label": "Visit Prothesis.ru",
        "guide_label": "Open the guide",
        "email_add": {
            "subject": "Email verification",
            "code_label": "Your verification code",
            "ttl_line": "Expires in: {ttl} minutes.",
            "ignore_line": "If this wasn't you, just ignore this email.",
        },
        "email_remove": {
            "subject": "Remove email from account",
            "code_label": "Your email removal code",
            "ttl_line": "Expires in: {ttl} minutes.",
            "ignore_line": "If this wasn't you, just ignore this email.",
        },
        "password_reset": {
            "subject": "Password reset",
            "code_label": "Your password reset code",
            "ttl_line": "Expires in: {ttl} minutes.",
            "ignore_line": "If this wasn't you, just ignore this email.",
        },
    },
}


def normalize_lang(lang: str | None, default: str = "ru") -> str:
    if not lang:
        return default
    v = str(lang).strip().lower()
    return v if v in SUPPORTED_LANGS else default


def _required_email_url(env_name: str) -> str:
    value = os.getenv(env_name, "").strip()
    if not value:
        raise ValueError(f"Email not configured. Set {env_name}.")
    return value


def _build_text_body(
    templates: dict,
    content: dict,
    greeting: str,
    code: str,
    ttl_min: int,
    landing_url: str,
    guide_url: str,
) -> str:
    return (
        f"{greeting}\n\n"
        f"{content['code_label']}: {code}\n"
        f"{content['ttl_line'].format(ttl=ttl_min)}\n\n"
        f"{content['ignore_line']}\n\n"
        f"{templates['signoff']}\n"
        f"{templates['team']}\n\n"
        f"{templates['landing_label']}: {landing_url}\n"
        f"{templates['guide_label']}: {guide_url}"
    )


def _build_html_body(
    templates: dict,
    content: dict,
    greeting: str,
    code: str,
    ttl_min: int,
    landing_url: str,
    guide_url: str,
) -> str:
    ttl_line = content["ttl_line"].format(ttl=ttl_min)
    return f"""
<div style="margin:0;padding:32px 16px;background:#f4efe6;">
  <div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e7dece;border-radius:24px;overflow:hidden;font-family:'Segoe UI',Arial,sans-serif;color:#1f2937;">
    <div style="padding:32px 32px 24px;background:linear-gradient(135deg,#fbf8f2 0%,#ffffff 100%);">
      <div style="font-size:13px;letter-spacing:0.12em;text-transform:uppercase;color:#8c6b44;margin-bottom:18px;">Prothesis.ru</div>
      <div style="font-size:24px;line-height:1.35;font-weight:600;margin:0 0 14px;">{escape(greeting)}</div>
      <div style="font-size:16px;line-height:1.6;color:#4b5563;margin:0 0 18px;">{escape(content['code_label'])}</div>
      <div style="display:inline-block;padding:16px 22px;border-radius:18px;background:#153f31;color:#ffffff;font-size:32px;line-height:1;font-weight:700;letter-spacing:0.24em;">{escape(code)}</div>
      <div style="margin-top:18px;font-size:15px;line-height:1.7;color:#4b5563;">
        {escape(ttl_line)}<br />
        {escape(content['ignore_line'])}
      </div>
    </div>
    <div style="padding:24px 32px 32px;border-top:1px solid #f0e7d8;">
      <div style="font-size:15px;line-height:1.7;color:#1f2937;margin-bottom:16px;">
        {escape(templates['signoff'])}<br />
        {escape(templates['team'])}
      </div>
      <div style="font-size:14px;line-height:1.9;">
        <a href="{landing_url}" style="color:#0f766e;text-decoration:none;">{escape(templates['landing_label'])}</a><br />
        <a href="{guide_url}" style="color:#0f766e;text-decoration:none;">{escape(templates['guide_label'])}</a>
      </div>
    </div>
  </div>
</div>
""".strip()


def build_email(
    lang: str | None,
    purpose: str,
    code: str,
    ttl_min: int,
    username: str | None = None,
) -> Tuple[str, str, str]:
    lng = normalize_lang(lang, default="ru")
    templates = _EMAIL_TEMPLATES.get(lng, _EMAIL_TEMPLATES["ru"])
    content = templates.get(purpose)
    if not content:
        templates = _EMAIL_TEMPLATES["ru"]
        content = templates["password_reset"]

    landing_url = _required_email_url("EMAIL_LANDING_URL")
    guide_url = _required_email_url("EMAIL_GUIDE_URL")

    greeting = (
        templates["greeting_named"].format(username=username)
        if username
        else templates["greeting_generic"]
    )

    subject = content["subject"]
    text = _build_text_body(
        templates,
        content,
        greeting,
        code,
        ttl_min,
        landing_url,
        guide_url,
    )
    html = _build_html_body(
        templates,
        content,
        greeting,
        code,
        ttl_min,
        landing_url,
        guide_url,
    )
    return subject, text, html
