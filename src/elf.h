#pragma once

#include <stdint.h>
#include "util.h"

// TODO: Move these into enums
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STT_FUNC 2
#define STT_NOTYPE 0

typedef uint8_t elf_class_t;
enum {
    ELF_CLASS_64 = 2,
};

typedef uint8_t elf_encoding_t;
enum {
    ELF_ENCODING_LITTLE = 1,
};

typedef uint8_t elf_abi_t;
enum {
    ELF_ABI_SYSV = 0,
};

typedef uint16_t elf_type_t;
enum {
    ELF_TYPE_RELOCATABLE = 1,
};

typedef uint16_t elf_arch_t;
enum {
    ELF_ARCH_X86_64 = 0x3e,
};

typedef struct {
    uint8_t magic[4];
    elf_class_t cls;
    elf_encoding_t encoding;
    uint8_t object_file_version;
    elf_abi_t abi;
    uint8_t abi_version;
    uint8_t _padding_1[7];
    elf_type_t type;
    elf_arch_t arch;
    uint32_t elf_version;
    addr_t entry_address;
    offset_t ph_offset;
    offset_t sh_offset;
    uint32_t flags;
    uint16_t header_size;
    uint16_t ph_entry_size;
    uint16_t ph_entry_count;
    uint16_t sh_entry_size;
    uint16_t sh_entry_count;
    uint16_t sh_shstrtab_index;
} elf_header_t;

typedef uint32_t elf_section_type_t;
enum {
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_RELA = 4,
};

typedef struct {
    uint32_t name_offset;
    elf_section_type_t type;
    uint64_t flags;
    addr_t virtual_addr;
    offset_t data_offset;
    uint64_t data_size;
    uint32_t link;
    uint32_t info;
    uint64_t align;
    uint64_t entry_size;
} elf_sh_t;

typedef struct {
    uint32_t name_offset;
    uint8_t info;  // TODO: Refactor into a struct with 2 4-bit fields, bind and type, create enums for them
    uint8_t other;
    uint16_t section_index;
    addr_t value;
    uint64_t size;
} elf_symbol_t;

typedef uint32_t elf_rela_type_t;
enum {
    R_X86_64_64 = 1,
    R_X86_64_PC32 = 2,
};

typedef struct {
    offset_t offset;
    uint64_t index_and_type;
    int64_t addend;
} elf_rela_t;
