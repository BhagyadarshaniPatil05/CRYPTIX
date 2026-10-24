from pydantic import BaseModel


class APKUploadResponse(BaseModel):
    message: str
    id: int
    filename: str
    sha256: str
    size: int
    status: str