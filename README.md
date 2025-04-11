# protobuf-pwn-tool

---

## 简介

基于pwntools编写的protobuf小工具，帮助ctfer快速逆向protobuf协议结构体。
仅可处理x64 Linux ELF。

也许是由于protobuf-c并不受google官方支持，pbtk工具在大部分情况下无法解决ctf pwn中的protobuf题
本工具基于pwntools编写，经笔者测试在绝大部分情况下可以实现一键识别，在无法自动分析的情况下可以手动提供ProtobufCMessageDescriptor结构体的地址

## 功能

- [x] 支持识别message、enum嵌套
- [x] 自动通过符号表定位**ProtobufCMessageDescriptor**(下文简称PMD)结构体
- [x] 通过magic字段自动识别PMD
- [x] 即使缺失符号表/magic识别失败，也可手动提供PMD(s)的地址  *(通常情况下它们很容易定位)*

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

***不提供PMD地址，自动通过符号表/magic字段识别：***  
`python3 pbpt.py -f test`

***手动获取PMD地址后传入并解析:***  
`python3 pbpt.py -f test -a 0xcafe 0xdead 0xbeef`

## 测试

可自行编译test_pack中的代码用于测试。
