import sys
from typing import Any, Dict, List, Optional

class Command:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

class Workflow(Command):
    def __init__(self, name: str, description: str = "A composite workflow"):
        super().__init__(name, description)
        self.commands: List[Command] = []

    def add(self, command: Command) -> 'Workflow':
        self.commands.append(command)
        return self

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        print(f"-> Entering Workflow: {self.name}")
        for cmd in self.commands:
            context = cmd.execute(context)
        print(f"-> Exiting Workflow: {self.name}")
        return context

class SetContextCommand(Command):
    def __init__(self, key: str, value: Any):
        super().__init__(f"set_{key}", f"Sets {key} in context")
        self.key = key
        self.value = value

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        context[self.key] = self.value
        print(f"  [Set] {self.key} = {self.value}")
        return context

class PrintContextCommand(Command):
    def __init__(self, key: str):
        super().__init__(f"print_{key}", f"Prints {key} from context")
        self.key = key

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        val = context.get(self.key, "<missing>")
        print(f"  [Print] {self.key}: {val}")
        return context

def main():
    set_name = SetContextCommand("name", "Alice")
    set_role = SetContextCommand("role", "Admin")
    print_name = PrintContextCommand("name")
    print_role = PrintContextCommand("role")

    init_workflow = Workflow("Init").add(set_name).add(set_role)
    display_workflow = Workflow("Display").add(print_name).add(print_role)

    main_workflow = Workflow("MainApp").add(init_workflow).add(display_workflow)

    print("Starting CLI Toolkit Demo...")
    final_context = main_workflow.execute({})
    print("Final Context:", final_context)

if __name__ == "__main__":
    main()
