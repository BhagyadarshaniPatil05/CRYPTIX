from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.similarity.similarity_service import (
    find_similar_apks
)

router = APIRouter(
    prefix="/similarity",
    tags=["Similarity"]
)


@router.get("/{twin_id}")
def get_similarity(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return find_similar_apks(
        db,
        twin_id
    )