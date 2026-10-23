from abc import ABCMeta, abstractmethod


class Repository(metaclass=ABCMeta):
    @abstractmethod
    def save(self, item: object) -> None:
        pass

    @abstractmethod
    def find_by_id(self, item_id: int) -> object | None:
        pass


class InMemoryRepository(Repository):
    def __init__(self) -> None:
        self._items: dict[int, object] = {}

    def save(self, item: object) -> None:
        item_id = len(self._items) + 1
        self._items[item_id] = item

    def find_by_id(self, item_id: int) -> object | None:
        return self._items.get(item_id)


class Service:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def create_item(self, item: object) -> None:
        self.repository.save(item)

    def get_item(self, item_id: int) -> object | None:
        return self.repository.find_by_id(item_id)


if __name__ == "__main__":
    repository = InMemoryRepository()
    service = Service(repository)

    service.create_item({"name": "example"})
    print(service.get_item(1))
