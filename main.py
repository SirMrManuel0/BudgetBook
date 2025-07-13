import keyring
import argparse

from budget_book import first_boot

parser = argparse.ArgumentParser()
parser.add_argument(
    "--mode",
    choices=["local", "server"],
    required=True
)

args = parser.parse_args()

if keyring.get_password("BudgetBook", "system_key") is None:
    first_boot()

print(args.mode)
