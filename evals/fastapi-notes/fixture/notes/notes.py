from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from .auth import Db, User

router = APIRouter()

SORTABLE = {"created", "title"}


class NoteIn(BaseModel):
    title: str
    body: str


@router.get("/")
def index(user: User, db: Db, sort: str = "created"):
    column = sort if sort in SORTABLE else "created"
    rows = db.execute(
        f"SELECT id, title, created FROM notes WHERE owner_id = ? ORDER BY {column} DESC",
        (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@router.get("/notes/{note_id}")
def show(note_id: int, user: User, db: Db):
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if note is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return dict(note)


@router.post("/notes", status_code=status.HTTP_201_CREATED)
def create(note: NoteIn, user: User, db: Db):
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
               (user["id"], note.title, note.body))
    db.commit()


@router.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete(note_id: int, user: User, db: Db):
    deleted = db.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?",
                         (note_id, user["id"])).rowcount
    db.commit()
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.get("/search")
def search(user: User, db: Db, q: str = "", limit: int = Query(20, ge=1, le=100)):
    rows = db.execute(
        f"SELECT id, title FROM notes WHERE owner_id = {user['id']} AND title LIKE '%{q}%' LIMIT ?",
        (limit,)).fetchall()
    return [dict(r) for r in rows]
