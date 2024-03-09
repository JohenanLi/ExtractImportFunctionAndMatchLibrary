# ExtractAllFunctions.py

from ghidra.program.model.listing import FunctionManager
from ghidra.util.task import ConsoleTaskMonitor

def extract_all_functions():
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True for forward iteration
    all_functions = []

    for function in functions:
        function_name = function.getName()
        if not function_name.startswith("FUN_"):
            all_functions.append(function_name)

    return all_functions

def write_to_file(all_functions, file_path):
    with open(file_path, "w") as f:
        for function_name in all_functions:
            f.write("{}\n".format(function_name))

if __name__ == "__main__":
    monitor = ConsoleTaskMonitor()
    all_functions = extract_all_functions()
    output_file = askFile("Select output file", "Save")
    write_to_file(all_functions, output_file.getAbsolutePath())
    print("All functions extracted to: {}".format(output_file.getAbsolutePath()))
