import sqlite3
from importlib.resources import files

from . import config


def connect():
    conn = sqlite3.connect(config.DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.executescript(files("notes").joinpath("schema.sql").read_text())
    print("Initialized the database.")
