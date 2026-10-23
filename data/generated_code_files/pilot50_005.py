import argparse


todo_items = []


def add_item(item):
    todo_items.append(item)
    print(f"Added item: {item}")


def remove_item(index):
    if index < 1 or index > len(todo_items):
        print("Invalid item number")
        return

    removed = todo_items.pop(index - 1)
    print(f"Removed item: {removed}")


def view_items():
    if not todo_items:
        print("Todo list is empty")
        return

    print("Todo List:")
    for i, item in enumerate(todo_items, start=1):
        print(f"{i}. {item}")


def main():
    parser = argparse.ArgumentParser(description="Simple Todo List App")
    parser.add_argument("action", choices=["add", "remove", "view"])
    parser.add_argument("--item", help="Item text to add")
    parser.add_argument("--index", type=int, help="Item number to remove")

    args = parser.parse_args()

    if args.action == "add":
        if not args.item:
            print("Please provide an item with --item")
        else:
            add_item(args.item)

    elif args.action == "remove":
        if args.index is None:
            print("Please provide an item number with --index")
        else:
            remove_item(args.index)

    elif args.action == "view":
        view_items()


if __name__ == "__main__":
    main()