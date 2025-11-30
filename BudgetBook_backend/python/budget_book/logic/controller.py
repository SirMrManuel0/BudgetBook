from typing import Optional

from backend.budget_book.logic import Database
from backend.budget_book.logic.user import User


class Controller:
    def __init__(self):
        self._databank: Database = Database()
        self._user: Optional[User] = None
        self._password: Optional[bytearray] = None

    def delete_password(self):
        for i in range(len(self._password)):
            self._password[i] = 0
        del self._password


