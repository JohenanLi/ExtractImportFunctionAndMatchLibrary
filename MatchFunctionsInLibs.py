import os
import subprocess

def get_shared_libraries(binary_path):
    try:
        output = subprocess.check_output(["readelf", "-d", binary_path])
        lines = output.decode().split('\n')
        libraries = [line.split('[')[1].split(']')[0] for line in lines if 'Shared library' in line]
        return libraries
    except subprocess.CalledProcessError:
        print(f"Error while processing {binary_path}")
        return []

def match_functions(lib_path, all_function_name, libraries):
    matched = {}
    unmatched = []

    for func in all_function_name:
        found = False
        for lib in libraries:
            so_file = os.path.join(lib_path, lib)
            if os.path.exists(so_file):
                with os.popen(f'nm -D {so_file}') as f:
                    for line in f:
                        if func in line:
                            matched[func] = lib
                            found = True
                            break
            if found:
                break
        if not found:
            unmatched.append(func)

    return matched, unmatched

def read_all_function_name(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

if __name__ == '__main__':
    binary_path = '/home/minipython/reproduce_cve/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
    lib_path = '/home/minipython/reproduce_cve/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/lib'

    all_function_name_path = "/mnt/d/code_proj/BinaryAnalysisiTool/all_function_name.txt"
    all_function_name = read_all_function_name(all_function_name_path)
    print(all_function_name)
    libraries = get_shared_libraries(binary_path)
    matched, unmatched = match_functions(lib_path, all_function_name, libraries)

    with open('matched_functions.txt', 'w') as f:
        for func, lib in matched.items():
            f.write(f'{func} -> {lib}.so\n')

    with open('unmatched_functions.txt', 'w') as f:
        for func in unmatched:
            f.write(func + '\n')

    print('Matching results saved to matched_functions.txt and unmatched_functions.txt')
