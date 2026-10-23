from typing import Union, Literal, Protocol, runtime_checkable


@runtime_checkable
class Drawable(Protocol):
    def draw(self) -> str:
        ...


class Circle:
    def __init__(self, radius: float):
        self.radius = radius

    def draw(self) -> str:
        return f"Drawing circle with radius {self.radius}"


class Square:
    def __init__(self, side: float):
        self.side = side

    def render(self) -> str:
        return f"Rendering square with side {self.side}"


ShapeType = Literal["circle", "square"]
ShapeOrString = Union[Drawable, str]


def process_shape(shape: ShapeOrString, shape_type: ShapeType) -> str:
    if isinstance(shape, Drawable):
        return f"Processing {shape_type}: {shape.draw()}"
    return f"Processing {shape_type}: {shape}"


def main() -> None:
    circle = Circle(5.0)
    square = Square(4.0)

    print(process_shape(circle, "circle"))
    print(process_shape("Just a string", "square"))

    print(f"Is Circle a Drawable? {isinstance(circle, Drawable)}")
    print(f"Is Square a Drawable? {isinstance(square, Drawable)}")


if __name__ == "__main__":
    main()
