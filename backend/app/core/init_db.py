from backend.app.core.database import engine
from backend.app.models.base import Base
from backend.app.models import User


def init_db():
    Base.metadata.create_all(bind=engine)