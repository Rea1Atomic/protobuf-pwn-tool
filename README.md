# protobuf-pwn-tool

[中文文档](README.zh-CN.md)

---

## Introduction

A protobuf helper built with `pwntools` to help CTF players quickly reverse-engineer protobuf message structures and generate `.proto` files with one command.  
Only `x64 Linux ELF` binaries are supported.

Because `protobuf-c` is not officially supported by Google, `pbtk` often fails on CTF pwn protobuf challenges.  
This tool is built on `pwntools` and, based on practical testing, can automatically identify descriptors in most cases.  
If automatic analysis fails, you can manually provide `ProtobufCMessageDescriptor` addresses.

## Features

- [x] Supports nested `message` and `enum` recognition
- [x] Automatically locates `ProtobufCMessageDescriptor` (PMD) via the symbol table
- [x] Automatically identifies PMD via magic field
- [x] Even when symbols are missing or magic detection fails, PMD address(es) can be provided manually *(usually easy to locate in practice)*

## Quick Start

`python3 pbpt.py -h`


```
usage: pbpt.py [-h] -f FILE [-a [ADDRESS ...]] [-d] [-v3]

A simple script helps CTFpwner deal with protobuf ELF, reverses proto structure and generates ".proto" files

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  inputfile
  -a [ADDRESS ...], --address [ADDRESS ...]
                        ELF's protobuf msg descriptor's virtual address, None for auto analyzation
  -d, --debug           use debug log level
  -v3, --version3       use pb3 syntax

```

***Auto-detect PMD via symbols or the magic field (without PMD addresses):***  
`python3 pbpt.py -f test`

***Provide PMD addresses manually and parse:***  
`python3 pbpt.py -f test -a 0xcafe 0xdead 0xbeef`

## Testing

Compile the code in `test_pack` for local testing.
