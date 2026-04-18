import re

import pytest

from app.services import auth_service
from app.services.common import ServiceError
from tests.factories import create_app_settings


def test_parse_hex_bytes_valid_even_length():
    result = auth_service.parse_hex_bytes("salt", "0a1b")
    assert result == bytes.fromhex("0a1b")


def test_parse_hex_bytes_valid_odd_length():
    result = auth_service.parse_hex_bytes("salt", "abc")
    assert result == bytes.fromhex("0abc")


def test_parse_hex_bytes_invalid_raises_service_error_400():
    with pytest.raises(ServiceError) as exc:
        auth_service.parse_hex_bytes("salt", "zz-not-hex")

    assert exc.value.status_code == 400
    assert exc.value.detail["error"] == "BAD_HEX"
    assert exc.value.detail["detail"] == "salt must be hex"


def test_generate_recovery_codes_default_count_and_format():
    codes = auth_service.generate_recovery_codes()

    assert len(codes) == 10
    assert len(set(codes)) == 10

    pattern = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
    assert all(pattern.fullmatch(code) for code in codes)


def test_generate_email_code_is_6_digits():
    code = auth_service.generate_email_code()

    assert len(code) == 6
    assert code.isdigit()


def test_mask_email_normal_email():
    assert auth_service.mask_email("john@example.com") == "j*******@example.com"


def test_mask_email_without_at():
    assert auth_service.mask_email("john-example.com") == "********"


def test_mask_email_with_empty_local_part():
    assert auth_service.mask_email("@example.com") == "********@example.com"


def test_get_user_lang_without_settings_returns_en(db_session, user_factory):
    user = user_factory(username="lang_user_1")

    result = auth_service.get_user_lang(db_session, user.id)

    assert result == "en"


def test_get_user_lang_reads_language_key(db_session, user_factory):
    user = user_factory(username="lang_user_2")
    create_app_settings(db_session, user.id, payload={"language": "ru"})

    result = auth_service.get_user_lang(db_session, user.id)

    assert result == "ru"


def test_get_user_lang_reads_lang_key(db_session, user_factory):
    user = user_factory(username="lang_user_3")
    create_app_settings(db_session, user.id, payload={"lang": "ru"})

    result = auth_service.get_user_lang(db_session, user.id)

    assert result == "ru"


def test_get_user_lang_returns_en_for_non_dict_payload(db_session, user_factory):
    user = user_factory(username="lang_user_4")
    create_app_settings(db_session, user.id, payload=["ru"])

    result = auth_service.get_user_lang(db_session, user.id)

    assert result == "en"
