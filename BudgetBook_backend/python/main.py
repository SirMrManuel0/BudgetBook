import keyring
import argparse

from budget_book import first_boot

parser = argparse.ArgumentParser()
parser.add_argument(
    "--mode",
    choices=["local", "server"],
    required=True
)

parser.add_argument(
    "--ip",
    default="127.0.0.1",
    required=False
)

parser.add_argument(
    "--port",
    type=int,
    default=8080,
    required=False
)

args = parser.parse_args()

if keyring.get_password("BudgetBook", "system_key") is None:
    first_boot()

print(args.mode)
print(args.ip)
print(args.port)
