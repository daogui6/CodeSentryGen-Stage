import argparse
import json
import os

TODO_FILE = 'todos.json'

def load_todos():
    if os.path.exists(TODO_FILE):
        with open(TODO_FILE, 'r') as f:
            return json.load(f)
    return []

def save_todos(todos):
    with open(TODO_FILE, 'w') as f:
        json.dump(todos, f)

def add_todo(args):
    todos = load_todos()
    todos.append(args.task)
    save_todos(todos)
    print(f'Added: {args.task}')

def remove_todo(args):
    todos = load_todos()
    try:
        removed = todos.pop(args.index)
        save_todos(todos)
        print(f'Removed: {removed}')
    except IndexError:
        print('Invalid index.')

def view_todos(args):
    todos = load_todos()
    if not todos:
        print('No todos found.')
        return
    for i, todo in enumerate(todos):
        print(f'{i}: {todo}')

def main():
    parser = argparse.ArgumentParser(description='Simple Todo List CLI')
    subparsers = parser.add_subparsers(dest='command')

    parser_add = subparsers.add_parser('add', help='Add a new todo')
    parser_add.add_argument('task', type=str, help='Task description')
    parser_add.set_defaults(func=add_todo)

    parser_remove = subparsers.add_parser('remove', help='Remove a todo by index')
    parser_remove.add_argument('index', type=int, help='Index of the todo to remove')
    parser_remove.set_defaults(func=remove_todo)

    parser_view = subparsers.add_parser('view', help='View all todos')
    parser_view.set_defaults(func=view_todos)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
