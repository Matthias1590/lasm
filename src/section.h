#pragma once

#include <stdlib.h>
#include <stdbool.h>
#include "sv.h"
#include "bb.h"
#include "symbol.h"
#include "relocation.h"
#include "elf.h"
#include "written.h"

typedef_written(elf_sh_t);

typedef struct {
	sv_t name;
	bb_t *data;
	bool merged;
	symbols_t symbols;
	relocations_t relocations;
	size_t index;
	written_t(elf_sh_t) elf_sh;
} section_t;

typedef struct {
	list_fields(section_t *);
} sections_t;

void section_free(section_t *section);
