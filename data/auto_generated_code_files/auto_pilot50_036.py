from abc import ABCMeta, abstractmethod

class MyClass(metaclass=ABCMeta):
    @abstractmethod
    def my_method(self) -> None:
        pass
