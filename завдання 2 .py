
import pefile

def analyze_pe(file_path):
    pe = pefile.PE(file_path)

    print(f"Analyzing {file_path}")
    print("Imported libraries and functions:")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"Library: {entry.dll.decode('utf-8')}")
            for imp in entry.imports:
                print(f" Function: {imp.name.decode('utf-8') if imp.name else 'Unknown'}")
    else:
        print("No imported libraries found.")

if __name__ == "__main__":
    file_path = input("Enter the path to the PE file: ")
    analyze_pe(file_path)

from construct import Struct, Int32ul, Int64ul, Array, CString, Pointer
import os

ELF_HEADER = Struct(
    'e_ident' / Array(16, 'B'),
    'e_type' / Int32ul,
    'e_machine' / Int32ul,
    'e_version' / Int32ul,
    'e_entry' / Int64ul,
    'e_phoff' / Int64ul,
    'e_shoff' / Int64ul,
    'e_flags' / Int32ul,
    'e_ehsize' / Int32ul,
    'e_phentsize' / Int32ul,
    'e_phnum' / Int32ul,
    'e_shentsize' / Int32ul,
    'e_shnum' / Int32ul,
    'e_shstrndx' / Int32ul
)

def analyze_elf(file_path):
    with open(file_path, 'rb') as f:
        elf_header = ELF_HEADER.parse(f.read(64))

    print(f"ELF File: {file_path}")
    print(f"Entry point: {hex(elf_header.e_entry)}")
    print(f"Section headers: {elf_header.e_shnum}")

if __name__ == "__main__":
    file_path = input("Enter the path to the ELF file: ")
    if os.path.exists(file_path):
        analyze_elf(file_path)
    else:
        print("File not found.")
