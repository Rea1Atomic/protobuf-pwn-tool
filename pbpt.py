from enum import Enum
from pwn import u32, u64, p32, ELF, context, log

import argparse

context.arch = 'amd64'
context.log_level = 'INFO'

#some var here for save user input 
msg_descriptor_addr_list : list[int] = []
file_name : str = ''
elf : ELF
v3 : bool = False

#global known descriptors
msg_descriptors : list = []
enum_descriptors : list = []


def read_cstr_by_vaddr(vaddr: int) -> bytes:
    res : bytes = b''
    b : bytes= elf.read(vaddr, 1)
    while b != b'\0':
        res += b
        vaddr+=1
        b = elf.read(vaddr, 1)
    return res


class ProtobufCType(Enum):
    INT32 = 0x0       # int32
    SINT32 = 0x1      # signed int32
    SFIXED32 = 0x2    # signed int32 (4 bytes)
    INT64 = 0x3       # int64
    SINT64 = 0x4      # signed int64
    SFIXED64 = 0x5    # signed int64 (8 bytes)
    UINT32 = 0x6      # unsigned int32
    FIXED32 = 0x7     # unsigned int32 (4 bytes)
    UINT64 = 0x8      # unsigned int64
    FIXED64 = 0x9     # unsigned int64 (8 bytes)
    FLOAT = 0xA       # float
    DOUBLE = 0xB      # double
    BOOL = 0xC        # boolean
    ENUM = 0xD        # enumerated type
    STRING = 0xE      # UTF-8 or ASCII string
    BYTES = 0xF       # arbitrary byte sequence
    MESSAGE = 0x10    # nested message


class ProtobufCLabel(Enum):
    REQUIRED = 0
    OPTIONAL = 1
    REPEATED = 2
    NONE = 3


class PbEnumDescriptor:
    def __init__(self, vaddr: int) -> None:
        log.debug(f'Initial a new enum by vaddr: {hex(vaddr)}')
        self.vaddr = vaddr
        name_addr = u64(elf.read(vaddr+0x10, 8))
        self.name : bytes = read_cstr_by_vaddr(name_addr)
        self.n_values : int = u32(elf.read(vaddr+0x28, 4))
        self.values_vaddr : int = elf.address + u64(elf.read(vaddr+0x30, 8))
        
        #load values
        self.values : dict[bytes, int] = {} # name : val
        for i in range(self.n_values):
            value_vaddr = self.values_vaddr + 0x18*i #0x18 for every values' size
            value_name = read_cstr_by_vaddr( u64(elf.read(value_vaddr, 8)) )
            value_value = u32(elf.read(value_vaddr+0x10, 4))
            self.values[value_name] = value_value

    def __str__(self) -> str:
        res = (
            f'Enum at {hex(self.vaddr)}:\n'
            f'\tname: {self.name.decode()}\n'
            f'\tvalues:\n'
        )
        
        for vn, vv in self.values.items():
            res += '\t\t'
            res += vn.decode()
            res += ' = '
            res += str(vv)
            res += '\n'
        
        return res
    
    def to_proto2(self) -> str:
        res = f'enum {self.name.decode()} {{\n'
        
        for vn, vv in self.values.items():
            res += '\t'
            res += vn.decode()
            res += ' = '
            res += str(vv)
            res += ';\n'
        
        res += '}\n'
        
        return res
    
    to_proto3 = to_proto2


class PbFieldDescriptor:
    def __init__(self, vaddr: int):
        log.debug(f'Try to initialize a new field by vaddr: {hex(vaddr)} ...')
        self.vaddr = vaddr
        name_addr = u64(elf.read(vaddr, 8))
        self.name = read_cstr_by_vaddr(name_addr)
        self.id = u32(elf.read(vaddr+8, 4))
        self.label : ProtobufCLabel = ProtobufCLabel(u32(elf.read(vaddr+0xC, 4))) 
        self.type : ProtobufCType = ProtobufCType(u32(elf.read(vaddr+0x10, 4)))
        self.default_val_addr : int = u64(elf.read(vaddr+0x28, 8))
        
        #for enum/msg field
        self.descriptor_addr : int = u64(elf.read(vaddr+0x20,8))
        self.descriptor : PbEnumDescriptor | PbMsgDescriptor
        if self.type == ProtobufCType.ENUM:
            log.info('Nested enum detected')
            self.descriptor = PbEnumDescriptor(elf.address+self.descriptor_addr)
            if self.descriptor not in enum_descriptors:
                log.success(f'Sucessfully found a new enum(name: {self.descriptor.name.decode()}) by field(name: {self.name.decode()}) at {hex(self.descriptor.vaddr)}')
                log.debug(str(self.descriptor))
                enum_descriptors.append(self.descriptor)
        if self.type == ProtobufCType.MESSAGE:
            log.info('Nested msg detected')
            self.descriptor = PbMsgDescriptor(elf.address+self.descriptor_addr)
            if self.descriptor.name not in [des.name for des in msg_descriptors]:
                log.success(f'Sucessfully found a new msg(name: {self.descriptor.name.decode()}) by field(name: {self.name.decode()}) at {hex(self.descriptor.vaddr)}')
                log.debug(str(self.descriptor))
                msg_descriptors.append(self.descriptor)

        
    def __str__(self) -> str:
        res = (
            f'Field at {hex(self.vaddr)}:\n'
            f'\tname: {self.name.decode()}\n'
            f'\tid: {self.id}\n'
            f'\tlabel: {str(self.label).split(".")[1]}\n'
            f'\ttype: {str(self.type).split(".")[1]}\n'
            f'\tdescriptor_addr: {hex(self.descriptor_addr)}\n'
        )
        
        if self.default_val_addr:
            res+=f'\tThis field has default_value, default_val_addr: {hex(self.default_val_addr)}\n'
        else:
            res+='\tThis field doesn\'t have default_value'

        return res


class PbMsgDescriptor:
    def __init__(self, vaddr: int):
        log.debug(f'Initial a new msg by vaddr: {hex(vaddr)}')
        self.vaddr = vaddr
        str_addr : int = u64(elf.read(vaddr+0x10, 8)) #name_addr
        self.name = read_cstr_by_vaddr(elf.address + str_addr)
        self.magic = u32(elf.read(vaddr, 4))
        if self.magic != 0x28aaeef9:
            raise Exception(f'{self.name.decode()} is not a msg descriptor, ingnored')
        self.n_fields = u32(elf.read(vaddr+0x30, 4))
        self.fields_vaddr = elf.address + u64(elf.read(vaddr+0x38, 8))
        
        log.debug(f'msg \'{self.name.decode()}\' metadata loaded, trying to solve its fields')
        #load fields:
        self.fields : list[PbFieldDescriptor] = []
        for i in range(self.n_fields):
            log.debug(f'solving {i} field...')
            self.fields.append(PbFieldDescriptor(self.fields_vaddr + 0x48*i)) #0x48 is protobuf's field size

    def __str__(self) -> str:
        res = (
            f'\nPbMsgDescriptor at {hex(self.vaddr)}:\n'
            f'\tname: {self.name.decode()}\n'
            f'\tmagic: {hex(self.magic)}\n'
            f'\tn_fields: {self.n_fields}\n'
            f'\tfields_vddr = {hex(self.fields_vaddr)}\n\n'
        )
        
        for fld in self.fields:
            for line in str(fld).split('\n'):
                res+='\t'+line + '\n'
        
        return res

    def to_proto2(self) -> str:
        #check the protobuf version
        res = f'message {self.name.decode()} {{\n'
        
        for field in self.fields:
            #for this field's label
            if field.label == ProtobufCLabel.NONE:
                res += '\trequired'
            else:
                res += '\t' + str(field.label).split('.')[1].lower()
            res += ' '
            
            # for this field's type
            # if type is enum or another message, it's type will be enum/msg name
            if field.type == ProtobufCType.ENUM or field.type == ProtobufCType.MESSAGE:
                res += field.descriptor.name.decode()
            # else type is ProtobufCType enum name 
            else:
                res += str(field.type).split('.')[1].lower()
            res += ' '
            
            # for this field's name and id
            res += field.name.decode()
            res += ' = '
            res += str(field.id)
            res += ';\n'
        
        res += '}\n'
        
        return res

    def to_proto3(self) -> str:
        #check the protobuf version
        res = f'message {self.name.decode()} {{\n'
        
        for field in self.fields:
            # for this field's label
            if field.label == ProtobufCLabel.REPEATED:
                res += '\trepeated '
            else:
                res += '\t'
            
            # for this field's type
            # if type is enum or another message, it's type will be enum/msg name
            if field.type == ProtobufCType.ENUM or field.type == ProtobufCType.MESSAGE:
                res += field.descriptor.name.decode()
            # else type is ProtobufCType enum name 
            else:
                res += str(field.type).split('.')[1].lower()
            res += ' '
            
            # for this field's name and id
            res += field.name.decode()
            res += ' = '
            res += str(field.id)
            res += ';\n'
        
        res += '}\n'
        
        return res


def save_to_proto2():
    with open(file_name+'.proto', 'w') as f:
        f.write('syntax = "proto2";\n\n')
        for enum in enum_descriptors:
            f.write(enum.to_proto2())
            f.write('\n')
        for pmd in msg_descriptors:
            f.write(pmd.to_proto2())
            f.write('\n')
    log.success(f'.proto saved to {file_name+".proto"}')


def save_to_proto3():
    with open(file_name+'.proto', 'w') as f:
        f.write('syntax = "proto3";\n\n')
        for enum in enum_descriptors:
            f.write(enum.to_proto3())
            f.write('\n')
        for pmd in msg_descriptors:
            f.write(pmd.to_proto3())
            f.write('\n')
    log.success(f'.proto saved to {file_name+".proto"}')


def handle_by_addr() -> None:
    for addr in msg_descriptor_addr_list:
        log.debug(f'Try to analyze with msg descriptor addr {hex(addr)}')
        try:
            pmd = PbMsgDescriptor(addr)
        except Exception as e:
            log.warning(f'Error occurred while analyzing msg_descriptor:\n {str(e)}')
            continue
        msg_descriptors.append(pmd)
        log.success(f'Sucessfully got a msg descriptor at addr {hex(addr)}')
        log.debug(f'Descriptor detail:\n{str(pmd)}')
    
    if not v3:
        save_to_proto2()
    else:
        save_to_proto3()
        

def handle_by_auto() -> None:
    #try to find pmd by symbol table
    for sym_name, sym_addr in elf.sym.items():
        if sym_name.endswith('__descriptor') and not sym_name.startswith('got'):
            msg_descriptor_addr_list.append(sym_addr)
            log.info(f'Found a msg descriptor by symbol: {sym_name} --> {hex(sym_addr)}')

    #try to find pmd by magic 0x28aaeef9
    magic = p32(0x28aaeef9)
    for addr in elf.search(magic):
            if not addr in msg_descriptor_addr_list:
                msg_descriptor_addr_list.append(addr)
                log.info(f'Found a msg descriptor by magic (addr: {hex(addr)})')
            
    if not len(msg_descriptor_addr_list):
        log.error('Auto analyzation can\'t find any msg descriptor!')
        exit()
    
    else:
        handle_by_addr()
        
if __name__ == '__main__':
    #arg process
    parser = argparse.ArgumentParser(description='A simple script helps CTFpwner deal with protobuf ELF, reverses proto structure and generates ".proto" files')
    parser.add_argument('-f', '--file', type=str, required=True, help='inputfile')
    parser.add_argument('-a', '--address', type=str, required=False, nargs='*', default='', help='ELF\'s protobuf msg descriptor\'s virtual address, None for auto analyzation')
    parser.add_argument('-d', '--debug', action='store_true', required=False, help='use debug log level')
    parser.add_argument('-v3', '--version3', action='store_true', required=False, help='use pb3 syntax')
    
    args = parser.parse_args()
    
    if args.debug:
        context.log_level = 'DEBUG'
    
    v3 = args.version3
    
    #try to load ELF
    try:
        file_name = args.file
        elf = ELF(args.file)
    except Exception as e:
        log.error('Error occurred while get ELF by input name:\nErr: ' + str(e))
        exit()
    
    #handle
    if not len(args.address):
        handle_by_auto()
    else:
        try:
            for a in args.address:
                if a.startswith('0x'):
                    msg_descriptor_addr_list.append(int(a, 16))
                else:
                    msg_descriptor_addr_list.append(int(a))
        except ValueError as ve:
            log.error('Invalid input!\nErr: ' + str(ve))
            exit()
        handle_by_addr()