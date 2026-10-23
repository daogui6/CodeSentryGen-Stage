from typing import Literal, Protocol, TypeAlias, Union, runtime_checkable


UserId: TypeAlias = int
JsonPrimitive: TypeAlias = Union[str, int, float, bool, None]
UserRole: TypeAlias = Literal["admin", "editor", "viewer"]


@runtime_checkable
class SupportsSave(Protocol):
    def save(self) -> None:
        ...


class User:
    def __init__(self, user_id: UserId, name: str, role: UserRole) -> None:
        self.user_id = user_id
        self.name = name
        self.role = role

    def save(self) -> None:
        print(f"Saving user {self.user_id}: {self.name}")


def serialize_value(value: JsonPrimitive) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def require_savable(obj: SupportsSave) -> None:
    obj.save()


def describe_role(role: UserRole) -> str:
    descriptions = {
        "admin": "Full access",
        "editor": "Can edit content",
        "viewer": "Read-only access",
    }
    return descriptions[role]


if __name__ == "__main__":
    user = User(1, "Alice", "admin")

    print(describe_role(user.role))
    print(serialize_value(True))

    if isinstance(user, SupportsSave):
        require_savable(user)
