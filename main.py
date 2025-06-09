import keyring

from budget_book import first_boot

if keyring.get_password("BudgetBook", "system_key") is None:
    first_boot()
