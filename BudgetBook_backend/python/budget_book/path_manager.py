import json
import os

from pylix.errors import assertion

from backend.budget_book.errors import BaseError

def get_path_abs(relative_path: str) -> str:
    """
    Returns the absolute path of a file or folder relative to path_manager.py.

    :param relative_path: Relative path to the file or folder.
    :return: Absolute path.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Directory of the executing script
    abs_path = os.path.join(script_dir, relative_path)
    abs_path = os.path.abspath(abs_path)
    if not os.path.exists(abs_path):
        raise Exception(f"Path '{abs_path}' does not exists.")
    return abs_path

def get_path_resource(*way) -> str:
    """
    Returns the absolute path of a ressource.
    The input should be the order of keys, under which the path is saved in resource.json.

    :param: way
    :return: abs path to ressource
    """
    assertion.assert_type_list(way, str, BaseError,
                               msg=f"Only strings can be in the way.")

    with open(get_path_abs("../resources/look_up.json"), "r", encoding="utf-8") as js:
        look_up: dict = json.load(js)
    sub_path: dict = look_up
    for i, step in enumerate(way):
        if isinstance(sub_path, dict) and step not in sub_path:
            raise Exception(f"There is no entry in 'resources.json' for '{step}' in order of '{way[:i+1]}\nOr there "
                            f"are too many args.")
        sub_path = sub_path[step]
    assertion.assert_type(sub_path, str, BaseError,
                          msg=f"There is no given path for this request in 'resources.json'")
    return get_path_abs("../resources" + "/" + str(sub_path))