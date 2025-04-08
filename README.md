# protobuf-pwn-tool

---

## 简介

基于pwntools编写的protobuf小工具，帮助ctfer快速逆向protobuf协议结构体。
仅可处理x64 Linux ELF。

~我从来来没觉得用pbtk开心过~ 这两年的题就没见有几道pbtk能梭出来的。  
遂写本工具，就算有时候(大部分)需要手动提供地址，也能省点事。  

## 功能

- [x] 支持识别message、enum嵌套
- [x] 自动通过符号表定位**ProtobufCMessageDescriptor**(下文简称PMD)结构体
- [x] 当符号表缺失时，可手动提供PMD(s)的地址  *(通常情况下它们很容易定位)*
- [ ] 通过magic字段自动识别PMD

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

***不提供PMD地址，自动通过符号表识别：***  
`python3 pbpt.py -f test`

***手动获取PMD地址后传入并解析:***  
`python3 pbpt.py -f test -a 0xcafe 0xdead 0xbeef`

## 测试

可自行编译test_pack中的代码用于测试。