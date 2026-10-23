from fastapi import APIRouter, status

from .auth import Db, User, UserIn, create_user

router = APIRouter(prefix="/admin")


@router.get("/users")
def users(user: User, db: Db):
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def add_user(new_user: UserIn, user: User, db: Db):
    create_user(db, new_user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, user: User, db: Db):
    db.execute("DELETE FROM notes WHERE owner_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
