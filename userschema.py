from jsonschema import validate
from jsonschema.exceptions import ValidationError
from jsonschema.exceptions import SchemaError

user_schema = {
    "type": "object",
    "properties": {
        "fname": {
            "type": "string",
        },
        "lname": {
            "type": "string",
        },
        "mphone": {
            "type": "string",
        },
        "phone": {
            "type": "string",
        },
        "email": {
            "type": "string",
            "format": "email"
        },
        "mcode": {
            "type": "string",
        },
        "pass": {
            "type": "string",
            "minlength": 5,
        },
        "state": {
            "type": "string",
        },
        "city": {
            "type": "string",
        },
        "address": {
            "type": "string",
        }
    },
    "required": ["email", "fname", "lname", "pass", "mcode", "mphone"],
    "additionalProperties": False
}


def validate_user(data):
    try:
        validate(data, user_schema)
    except ValidationError as e:
        return {'ok': False, 'message': e}
    except SchemaError as e:
        return {'ok': False, 'message': e}
    return True
