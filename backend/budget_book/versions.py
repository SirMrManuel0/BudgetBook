import json
from backend.budget_book.path_manager import get_path_abs

def _get_versions_dict() -> dict:
    with open(get_path_abs("../versions.json"), "r") as f:
        versions: dict = json.load(f)
    return versions

def get_file_versions() -> str:
    return _get_versions_dict()["file_version"]
