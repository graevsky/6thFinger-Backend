from types import SimpleNamespace

from app.models.user import User


class FakeMinioResponse:
    def __init__(self, chunks):
        self._chunks = chunks
        self.closed = False
        self.released = False

    def stream(self, chunk_size):
        for chunk in self._chunks:
            yield chunk

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


class FakeMinioClient:
    def __init__(self):
        self.put_calls = []
        self.remove_calls = []
        self.stat_content_type = "image/jpeg"
        self.stat_should_fail = False
        self.get_should_fail = False
        self.response = FakeMinioResponse([b"chunk1", b"chunk2"])

    def put_object(self, bucket, key, data, length, content_type):
        payload = data.read()
        self.put_calls.append(
            {
                "bucket": bucket,
                "key": key,
                "length": length,
                "content_type": content_type,
                "payload": payload,
            }
        )

    def remove_object(self, bucket, key):
        self.remove_calls.append(
            {
                "bucket": bucket,
                "key": key,
            }
        )

    def stat_object(self, bucket, key):
        if self.stat_should_fail:
            raise RuntimeError("stat failed")
        return SimpleNamespace(content_type=self.stat_content_type)

    def get_object(self, bucket, key):
        if self.get_should_fail:
            raise RuntimeError("get failed")
        return self.response


def test_upload_avatar_rejects_missing_content_type(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="avatar_user_1")
    auth_as(user)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.jpg", b"fake-image-bytes", "")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Missing file"}


def test_upload_avatar_rejects_unsupported_file_type(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="avatar_user_2")
    auth_as(user)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.gif", b"gif-bytes", "image/gif")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Unsupported file type"}


def test_upload_avatar_rejects_empty_file(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="avatar_user_3")
    auth_as(user)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.jpg", b"", "image/jpeg")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Empty file"}


def test_upload_avatar_rejects_file_too_large(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="avatar_user_4")
    auth_as(user)

    too_big = b"x" * (6 * 1024 * 1024 + 1)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.jpg", too_big, "image/jpeg")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "File too large"}


def test_upload_avatar_success_for_jpeg(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_5")
    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.jpg", b"jpeg-bytes", "image/jpeg")},
    )

    assert response.status_code == 200
    data = response.json()

    expected_key = f"avatars/{user.id}.jpg"
    assert data == {
        "key": expected_key,
        "content_type": "image/jpeg",
    }

    assert len(fake_minio.put_calls) == 1
    put_call = fake_minio.put_calls[0]
    assert put_call["key"] == expected_key
    assert put_call["content_type"] == "image/jpeg"
    assert put_call["payload"] == b"jpeg-bytes"

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key == expected_key


def test_upload_avatar_success_for_png_uses_png_extension(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_6")
    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.png", b"png-bytes", "image/png")},
    )

    assert response.status_code == 200
    data = response.json()

    expected_key = f"avatars/{user.id}.png"
    assert data == {
        "key": expected_key,
        "content_type": "image/png",
    }

    assert len(fake_minio.put_calls) == 1
    assert fake_minio.put_calls[0]["key"] == expected_key

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key == expected_key


def test_upload_avatar_success_for_webp_uses_webp_extension(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_7")
    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.webp", b"webp-bytes", "image/webp")},
    )

    assert response.status_code == 200
    data = response.json()

    expected_key = f"avatars/{user.id}.webp"
    assert data == {
        "key": expected_key,
        "content_type": "image/webp",
    }

    assert len(fake_minio.put_calls) == 1
    assert fake_minio.put_calls[0]["key"] == expected_key

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key == expected_key


def test_upload_avatar_removes_old_avatar_when_extension_changes(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_8")
    user.avatar_key = f"avatars/{user.id}.jpg"
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.png", b"png-bytes", "image/png")},
    )

    assert response.status_code == 200

    assert len(fake_minio.remove_calls) == 1
    assert fake_minio.remove_calls[0]["key"] == f"avatars/{user.id}.jpg"

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key == f"avatars/{user.id}.png"


def test_upload_avatar_ignores_remove_error_for_old_avatar(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_9")
    user.avatar_key = f"avatars/{user.id}.jpg"
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    auth_as(user)

    fake_minio = FakeMinioClient()

    def broken_remove(bucket, key):
        raise RuntimeError("remove failed")

    fake_minio.remove_object = broken_remove
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.post(
        "/avatar/",
        files={"file": ("avatar.png", b"png-bytes", "image/png")},
    )

    assert response.status_code == 200
    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key == f"avatars/{user.id}.png"


def test_get_avatar_returns_404_when_user_has_no_avatar(
    client,
    user_factory,
    auth_as,
):
    user = user_factory(username="avatar_user_10")
    auth_as(user)

    response = client.get("/avatar/")

    assert response.status_code == 404
    assert response.json() == {"detail": "No avatar found"}


def test_get_avatar_success_returns_stream_and_content_type_from_stat(
    client,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_11")
    user.avatar_key = f"avatars/{user.id}.jpg"
    auth_as(user)

    fake_minio = FakeMinioClient()
    fake_minio.stat_content_type = "image/webp"
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.get("/avatar/")

    assert response.status_code == 200
    assert response.content == b"chunk1chunk2"
    assert response.headers["content-type"] == "image/webp"
    assert response.headers["cache-control"] == "no-store"
    assert fake_minio.response.closed is True
    assert fake_minio.response.released is True


def test_get_avatar_falls_back_to_jpeg_when_stat_fails(
    client,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_12")
    user.avatar_key = f"avatars/{user.id}.jpg"
    auth_as(user)

    fake_minio = FakeMinioClient()
    fake_minio.stat_should_fail = True
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.get("/avatar/")

    assert response.status_code == 200
    assert response.content == b"chunk1chunk2"
    assert response.headers["content-type"] == "image/jpeg"


def test_get_avatar_returns_404_when_object_missing_in_storage(
    client,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_13")
    user.avatar_key = f"avatars/{user.id}.jpg"
    auth_as(user)

    fake_minio = FakeMinioClient()
    fake_minio.get_should_fail = True
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.get("/avatar/")

    assert response.status_code == 404
    assert response.json() == {"detail": "Avatar not found"}


def test_delete_avatar_success_removes_from_storage_and_clears_key(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_14")
    user.avatar_key = f"avatars/{user.id}.jpg"
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.delete("/avatar/")

    assert response.status_code == 204
    assert response.content == b""

    assert len(fake_minio.remove_calls) == 1
    assert fake_minio.remove_calls[0]["key"] == f"avatars/{user.id}.jpg"

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key is None


def test_delete_avatar_without_existing_key_still_returns_204(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_15")
    auth_as(user)

    fake_minio = FakeMinioClient()
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.delete("/avatar/")

    assert response.status_code == 204
    assert response.content == b""
    assert fake_minio.remove_calls == []

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key is None


def test_delete_avatar_ignores_storage_remove_errors(
    client,
    db_session,
    user_factory,
    auth_as,
    monkeypatch,
):
    user = user_factory(username="avatar_user_16")
    user.avatar_key = f"avatars/{user.id}.jpg"
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    auth_as(user)

    fake_minio = FakeMinioClient()

    def broken_remove(bucket, key):
        raise RuntimeError("remove failed")

    fake_minio.remove_object = broken_remove
    monkeypatch.setattr("app.routes.avatar.get_minio", lambda: fake_minio)

    response = client.delete("/avatar/")

    assert response.status_code == 204

    updated_user = db_session.query(User).filter_by(id=user.id).first()
    assert updated_user.avatar_key is None
