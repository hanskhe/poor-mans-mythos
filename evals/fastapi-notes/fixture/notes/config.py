import os

DATABASE = os.environ.get("NOTES_DB", "notes.sqlite3")
SECRET_KEY = "n0tes-dev-4f9a2c71e8"
DEBUG = True
