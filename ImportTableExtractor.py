# ImportTableExtractor.py

from ghidra.program.model.symbol import SymbolUtilities
from ghidra.util.task import ConsoleTaskMonitor

def extract_import_table():
    symbol_table = currentProgram.getSymbolTable()
    external_symbols = symbol_table.getExternalSymbols()
    import_table = []

    for symbol in external_symbols:
        if symbol.isExternal():
            library_name = symbol.getParentNamespace().getName()
            function_name = symbol.getName()
            import_table.append((library_name, function_name))

    return import_table


def write_to_file(import_table, file_path):
    with open(file_path, "w") as f:
        for library_name, function_name in import_table:
            f.write("{},{}\n".format(library_name, function_name))


if __name__ == "__main__":
    monitor = ConsoleTaskMonitor()
    import_table = extract_import_table()
    output_file = askFile("Select output file", "Save")
    write_to_file(import_table, output_file.getAbsolutePath())
    print("Import table extracted to: {}".format(output_file.getAbsolutePath()))
