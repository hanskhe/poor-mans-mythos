import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pwdlib import PasswordHash
from pydantic import BaseModel

from .db import get_db

router = APIRouter(prefix="/auth")
hasher = PasswordHash.recommended()

Db = Annotated[sqlite3.Connection, Depends(get_db)]


class UserIn(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class Credentials(BaseModel):
    username: str
    password: str


def create_user(db: sqlite3.Connection, user: UserIn):
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
               (user.username, hasher.hash(user.password), int(user.is_admin)))
    db.commit()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserIn, db: Db):
    create_user(db, user)


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(creds: Credentials, request: Request, db: Db):
    user = db.execute("SELECT * FROM users WHERE username = ?", (creds.username,)).fetchone()
    if user is None or not hasher.verify(creds.password, user["password"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    request.session.clear()
    request.session["user_id"] = user["id"]


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request):
    request.session.clear()


def current_user(request: Request, db: Db) -> sqlite3.Row:
    user_id = request.session.get("user_id")
    user = None if user_id is None else db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    return user


User = Annotated[sqlite3.Row, Depends(current_user)]
