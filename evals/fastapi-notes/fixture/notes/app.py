from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from . import admin, auth, config, importer, notes

app = FastAPI(title="Notes", debug=config.DEBUG)
app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY)
for module in (auth, notes, importer, admin):
    app.include_router(module.router)
