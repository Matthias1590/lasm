#pragma once

#include "list.h"
#include "written.h"
#include "elf.h"
#include "sv.h"
#include "util.h"

typedef_written(elf_rela_t);

typedef struct {
	offset_t patch_offset;
	elf_rela_type_t patch_type;
	int64_t address_offset;
	sv_t symbol_name;
	written_t(elf_rela_t) elf_rela;
} relocation_t;

typedef struct {
	list_fields(relocation_t *);
} relocations_t;
