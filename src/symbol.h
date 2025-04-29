#pragma once

#include <stdlib.h>
#include <stdint.h>
#include "list.h"
#include "written.h"
#include "elf.h"
#include "sv.h"

typedef_written(elf_symbol_t);

typedef struct {
	sv_t name;
	addr_t address;
	uint64_t size;
	size_t index;
	written_t(elf_symbol_t) elf_symbol;
} symbol_t;

typedef struct {
	list_fields(symbol_t *);
} symbols_t;
