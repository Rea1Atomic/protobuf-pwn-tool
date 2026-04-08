# protobuf-pwn-tool

[English](README.md)

---

## 简介

基于 `pwntools` 编写的 protobuf 小工具，帮助 CTFer 快速逆向 protobuf 消息结构，并一键生成 `.proto` 文件。  
仅支持 `x64 Linux ELF`。

也许是由于 `protobuf-c` 并不受 Google 官方支持，`pbtk` 在大部分情况下无法解决 CTF pwn 中的 protobuf 题。  
本工具基于 `pwntools` 编写，经测试在绝大部分情况下可以自动识别描述符；在无法自动分析时，也可以手动提供 `ProtobufCMessageDescriptor` 结构体地址。

## 功能

- [x] 支持识别 `message`、`enum` 嵌套
- [x] 自动通过符号表定位 `ProtobufCMessageDescriptor`（下文简称 PMD）结构体
- [x] 通过 magic 字段自动识别 PMD
- [x] 即使缺失符号表或 magic 识别失败，也可手动提供 PMD 地址（通常较容易定位）

## 快速开始

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

***不提供 PMD 地址时，自动通过符号表或 magic 字段识别：***  
`python3 pbpt.py -f test`

***手动获取 PMD 地址后传入并解析：***  
`python3 pbpt.py -f test -a 0xcafe 0xdead 0xbeef`

## 测试

可自行编译 `test_pack` 中的代码用于测试。
