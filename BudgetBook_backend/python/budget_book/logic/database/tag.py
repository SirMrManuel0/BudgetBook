import uuid

class Tag:
    def __init__(self, name: str, tag_id: str = str(uuid.uuid4())):
        self.name: str = name
        self.tag_id: str = tag_id
