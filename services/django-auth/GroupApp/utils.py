from pydantic import ValidationError

def validate(schema, data):
    try:
        return schema(**data), None
    except ValidationError as e:
        return None, e.errors()
    