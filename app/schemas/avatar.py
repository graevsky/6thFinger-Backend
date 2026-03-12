from pydantic import BaseModel


class AvatarOut(BaseModel):
    key: str
    content_type: str
