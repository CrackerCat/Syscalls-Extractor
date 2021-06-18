#!/usr/bin/env python3

import r2pipe
import argparse
import os
import sys

syscalls = {
    "ntoskrnl.exe": [
        "ZwOpenProcess",
        "ZwCreateThreadEx",
        "ZwWriteVirtualMemory",
        "ZwAllocateVirtualMemory",
        "ZwCreateSection",
        "ZwMapViewOfSection",
        "ZwCreateProcess",
        "ZwProtectVirtualMemory"
    ],
}


def get_function_address(r2, function):
    function_info = r2.cmd(f"is~{function}")
    split_function_info = function_info.split('\r\n')
    parsed_split_function_info = [i for i in split_function_info if i]

    if parsed_split_function_info:
        for line in parsed_split_function_info:
            split_line = line.split()
            if len(split_line) != 8:
                print(f"[-] Error parsing function info - expected 8 columns but got {len(split_line)}:\n{line} ")
                r2.quit()
                sys.exit(-1)
            if split_line[7].strip() == function:
                return split_line[2].strip()


def get_function_address_from_debug_symbols(r2, function):
    r2.cmd('idpd')
    function_debug_symbols = r2.cmd(f'idpi~{function}')
    split_function_debug_symbols = function_debug_symbols.split('\r\n')
    parsed_split_function_debug_symbols = [i for i in split_function_debug_symbols if i]

    if not parsed_split_function_debug_symbols:
        return None
    for function_debug_symbol in parsed_split_function_debug_symbols:
        split_function_debug_symbol = function_debug_symbol.split()
        if len(split_function_debug_symbol) != 4:
            print(f"[-] Error parsing debug info - expected four columns: {function_debug_symbol}")
            return None
        if split_function_debug_symbol[3].strip() == function:
            return split_function_debug_symbol[0].strip()


def parse_function_opcodes(pe, function, function_opcodes):
    parsed_function_opcodes = function_opcodes.split('\r\n')
    parsed_function_opcodes = [i for i in parsed_function_opcodes if i]

    if len(parsed_function_opcodes) < 2:
        print(f"[-] Error parsing function opcodes - expected at least two opcodes (mov and jmp): {function_opcodes}")
        return None

    syscall_number_mov = parsed_function_opcodes[-2]

    if "mov eax" not in syscall_number_mov:
        print(f"Error finding syscall {pe} : {function} - instruction before first jmp is not a mov eax: {syscall_number_mov}")
        return None

    return syscall_number_mov.split(',')[1].strip().replace("0x", "")


def print_syscall_number(pe_directory, pe, functions):

    if not pe_directory.endswith(os.path.sep):
        pe_directory = pe_directory + os.path.sep

    r2 = r2pipe.open(f'{pe_directory}{pe}', flags=['-2'])

    for function in functions:

        function_address = get_function_address(r2, function)

        if not function_address:
            function_address = get_function_address_from_debug_symbols(r2, function)

        if not function_address:
            print(f"[-] Not Found = {pe} : {function}")
            continue

        r2.cmd(f"s {function_address}")
        function_opcodes = r2.cmd(f"piuq jmp")

        if not function_opcodes:
            continue

        syscall_number = parse_function_opcodes(pe, function, function_opcodes)

        if not syscall_number:
            continue

        print(f"[*] {int(syscall_number, 16)}\t(0x{syscall_number}) = {pe} : {function}")

    r2.quit()


def main(args):

    print(f"[*] Printing syscall numbers for {','.join(syscalls.keys())} in {args.pe_directory}\n")

    for pe, functions in syscalls.items():
        print_syscall_number(args.pe_directory, pe, functions)

    print("\n[+] Done")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Automatically extracts syscall numbers for an OS')
    parser.add_argument('-d', '--pe-directory', default=r'C:\Windows\System32')
    args = parser.parse_args()

    main(args)
