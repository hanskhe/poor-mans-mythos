import yaml
from fastapi import APIRouter, HTTPException, UploadFile, status

from .auth import Db, User

router = APIRouter()


@router.post("/import")
async def import_bundle(bundle: UploadFile, user: User, db: Db):
    notes = yaml.safe_load(await bundle.read())
    if not isinstance(notes, list):
        raise HTTPException(status.HTTP_400_BAD_REQUEST)
    for note in notes:
        db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                   (user["id"], str(note.get("title", "")), str(note.get("body", ""))))
    db.commit()
    return {"imported": len(notes)}
