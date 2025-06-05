import uuid
from datetime import datetime
from typing import Iterable, Optional

from budget_book.logic.databank.tag import Tag


class Transaction:
    def __init__(self, sender: dict, receiver: dict, amount: int,
                 transaction_id: str = str(uuid.uuid4()), tags: tuple = tuple(), description: str = ""):
        self.date: datetime = datetime.now()
        self.sender: dict = sender
        self.receiver: dict = receiver
        self.amount: int = amount
        self.transaction_id: str = transaction_id
        self.tags: list = list(tags)
        self.description = description

    @classmethod
    def create_receiver(cls, name: str, iban: str, bank: str, managed_account: bool, tags: Iterable[Tag],
                        account_name: Optional[str] = None, account_id: Optional[str] = None) -> dict:
        return {
            "name": name,
            "account_name": account_name,
            "account_id": account_id,
            "iban": iban,
            "bank": bank,
            "managed_account": managed_account,
            "tags": tags
        }

    @classmethod
    def create_sender(cls, name: str, iban: str, bank: str, managed_account: bool, tags: Iterable[Tag],
                      account_name: Optional[str] = None, account_id: Optional[str] = None) -> dict:
        return {
            "name": name,
            "account_name": account_name,
            "account_id": account_id,
            "iban": iban,
            "bank": bank,
            "managed_account": managed_account,
            "tags": tags
        }

class RepetitionObject:
    def __init__(self, start_date: datetime):
        self.start_date = start_date
        self.interval = dict()

    def create_interval(self, days: int, weeks: int, months: int, years: int,
                        decades: int, centuries: int, millennia: int): # lol
        self.interval = {
            "days": days,
            "weeks": weeks,
            "months": months,
            "years": years,
            "decades": decades,
            "centuries": centuries,
            "millennia": millennia
        }

class StandingOrder(Transaction):
    def __init__(self, sender: dict, receiver: dict, amount: int, repetition: RepetitionObject,
                 transaction_id: str = str(uuid.uuid4()), tags: tuple = tuple(), description: str = ""):
        super().__init__(sender=sender, receiver=receiver, amount=amount,
                         transaction_id=transaction_id, tags=tags, description=description)
        self.repetition = repetition
