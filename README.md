# Syscalls-Extractor

Quick script for automatically extracting syscall numbers for an OS

```
$ python3 .\syscalls-extractor.py --help
usage: syscalls-extractor.py [-h] [-d PE_DIRECTORY]

Automatically extracts syscall numbers for an OS

optional arguments:
  -h, --help            show this help message and exit
  -d PE_DIRECTORY, --pe-directory PE_DIRECTORY
```

```
$ python3 .\syscalls-extractor.py
[*] Printing syscall numbers for ntoskrnl.exe in C:\Windows\System32

[*] 38  (0x26) = ntoskrnl.exe : ZwOpenProcess
[*] 193 (0xc1) = ntoskrnl.exe : ZwCreateThreadEx
[*] 58  (0x3a) = ntoskrnl.exe : ZwWriteVirtualMemory
[*] 24  (0x18) = ntoskrnl.exe : ZwAllocateVirtualMemory
[*] 74  (0x4a) = ntoskrnl.exe : ZwCreateSection
[*] 40  (0x28) = ntoskrnl.exe : ZwMapViewOfSection
[*] 185 (0xb9) = ntoskrnl.exe : ZwCreateProcess
[*] 80  (0x50) = ntoskrnl.exe : ZwProtectVirtualMemory

[+] Done
```
