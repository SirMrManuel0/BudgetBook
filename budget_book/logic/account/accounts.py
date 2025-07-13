import uuid
from typing import Iterable
from pylix.errors import TODO

from budget_book.logic.database.tag import Tag
from budget_book.logic.account.transactions import RepetitionObject
from budget_book.logic.user import User


class Account:
    def __init__(self, name: str, bank: str, currency: str,
                 start_cents: int = 0, iban: str = "XXxx-xxxx-xxxx-xxxx-xxxx-xx", account_id: str = str(uuid.uuid4())):
        self.account_id: str = account_id
        self.bank: str = bank
        self.name: str = name
        self.currency: str = currency
        self._cents: int = start_cents
        self._IBAN: str = iban
        self._transactions: list = list()
        self._standing_orders: list = list()
        self._tags: list = list()

    def add_tag(self, tag: Tag) -> None:
        self._tags.append(tag)

    def add_tags(self, tags: Iterable[Tag]) -> None:
        for tag in tags:
            self.add_tag(tag)

    def set_tags(self, tags: Iterable[Tag]) -> None:
        self.clear_tags()
        self.add_tags(tags)

    def clear_tags(self) -> None:
        self._tags = list()

    def remove_tag(self, tag: Tag) -> None:
        self._tags.remove(tag)

    @TODO
    def do_transaction(self, amount: int, receiver: dict, tags: Iterable[Tag]):
        ...

    @TODO
    def receive_transaction(self, amount: int, sender: dict, tags: Iterable[Tag]):
        ...

    @TODO
    def do_db_entry(self):
        ...

class SharedAccount(Account):
    def __init__(self, name: str, bank: str, currency: str, users: Iterable[User],
                 start_cents: int = 0, iban: str = "XXxx-xxxx-xxxx-xxxx-xxxx-xx", account_id: str = str(uuid.uuid4())):
        super().__init__(name=name, bank=bank, currency=currency,
                         start_cents=start_cents, iban=iban, account_id=account_id)
        self.users: list = list(users)

class ChildAccount(Account):
    def __init__(self, name: str, bank: str, currency: str, parent_account: Account,
                 start_cents: int = 0, iban: str = "XXxx-xxxx-xxxx-xxxx-xxxx-xx", account_id: str = str(uuid.uuid4())):
        super().__init__(name=name, bank=bank, currency=currency,
                         start_cents=start_cents, iban=iban, account_id=account_id)
        self.parent_account = parent_account

class SavingsAccount(Account):
    def __init__(self, name: str, bank: str, currency: str, interest_rate_pa: str, repetition: RepetitionObject,
                 start_cents: int = 0, iban: str = "XXxx-xxxx-xxxx-xxxx-xxxx-xx", account_id: str = str(uuid.uuid4())):
        super().__init__(name=name, bank=bank, currency=currency,
                         start_cents=start_cents, iban=iban, account_id=account_id)
        self.interest_rate_pa = interest_rate_pa
        self.repetition = repetition

class DepositAccount(Account):
    def __init__(self, name: str, bank: str, currency: str, interest_rate_pa: str,
                 repetition: RepetitionObject, duration: RepetitionObject,
                 start_cents: int = 0, iban: str = "XXxx-xxxx-xxxx-xxxx-xxxx-xx", account_id: str = str(uuid.uuid4())):
        super().__init__(name=name, bank=bank, currency=currency,
                         start_cents=start_cents, iban=iban, account_id=account_id)
        self.interest_rate_pa = interest_rate_pa
        self.repetition = repetition
        self.duration = duration
