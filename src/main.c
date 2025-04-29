#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include "util.h"
#include "elf.h"
#include "written.h"
#include "section.h"
#include "symbol.h"
#include "relocation.h"
#include "list.h"
#include "sv.h"
#include "bb.h"

typedef_written(elf_header_t);

/// @brief Prints usage of the program.
/// @param f The file to print to.
void print_usage(FILE *f) {
	fprintf(f, "Usage: lasm <file>\n");
}

sv_t sv_str(const char *str) {
	return (sv_t) {
		.data = (char *)str,
		.size = strlen(str),
	};
}

/// @brief Chops a token from the string.
/// @param string The string to chop from. The delimiter will be removed.
/// @param delim A string containing delimiter characters.
/// @return The chopped token. Without the delimiter.
sv_t chop_until(sv_t *string, const char *delim) {
	char *end = strpbrk(string->data, delim);
	if (end == NULL || end >= (char *)string->data + string->size) {
		end = (char *)string->data + string->size;
	}

	size_t line_size = end - (char *)string->data;
	sv_t line = { .data = string->data, .size = line_size };
	string->data = (char *)string->data + line_size + 1;
	string->size -= line_size + 1;
	return line;
}

sv_t chop_n(sv_t *string, size_t n) {
	if (string->size < n) {
		n = string->size;
	}

	sv_t chopped = (sv_t) {
		.data = string->data,
		.size = n,
	};

	string->data += n;
	string->size -= n;

	return chopped;
}

bool is_space_char(char c) {
	return c == ' ' || c == '\t';
}

/// @brief Strips leading and trailing whitespace from a string.
/// @param string The string to strip.
/// @return The stripped string.
sv_t stripped(sv_t string) {
	while (string.size > 0 && is_space_char(string.data[0])) {
		string.data++;
		string.size--;
	}
	while (string.size > 0 && is_space_char(string.data[string.size - 1])) {
		string.size--;
	}
	return string;
}

void strip(sv_t *sv) {
	*sv = stripped(*sv);
}

bool startswith(sv_t string, sv_t start) {
	if (string.size < start.size) {
		return false;
	}
	return memcmp(string.data, start.data, start.size) == 0;
}

/// @brief Extracts a label name from a line containing a label definition.
/// @param line The line to extract the label name from.
/// @param label The sv to store the label name.
/// @return True if the line was a label definition, false otherwise.
bool get_label_name(sv_t line, sv_t *label) {
	if (line.size == 0) {
		return false;
	}
	if (line.data[line.size - 1] != ':') {
		return false;
	}

	if (label) {
		label->data = line.data;
		label->size = line.size - 1;
	}
	return true;
}

bool chop_start(sv_t *string, sv_t start) {
	if (!startswith(*string, start)) {
		return false;
	}

	chop_n(string, start.size);
	return true;
}

bool chop_i64(sv_t *string, int64_t *value) {
	char *end;
	*value = strtoll(string->data, &end, 0);
	if (end > string->data + string->size) {
		end = string->data + string->size;
	}
	if (end == string->data) {
		return false;
	}
	string->size -= end - string->data;
	string->data = end;
	return true;
}

bool is_ident_char(char c, bool is_first_char) {
	if (isalpha(c) || c == '_') {
		return true;
	}

	return is_first_char
		? isdigit(c)
		: false;
}

bool chop_ident(sv_t *sv, sv_t *ident) {
	if (sv->size == 0) {
		return false;
	}
	if (!is_ident_char(sv->data[0], true)) {
		return false;
	}

	size_t size = 1;
	while (size <= sv->size && is_ident_char(sv->data[size], false)) {
		size++;
	}

	*ident = chop_n(sv, size);
	return true;
}

bool chop_string(sv_t *sv, sv_t *string) {
	if (!chop_start(sv, sv_str("\""))) {
		return false;
	}

	char *new_string = malloc(sv->size + 1);  // TODO: Bound check? Also never freed

	bool escape = false;
	size_t j = 0;
	size_t i;
	for (i = 0; i < sv->size; i++) {
		if (escape) {
			switch (sv->data[i]) {
				case 'n':
					new_string[j++] = '\n';
					break;
				case 't':
					new_string[j++] = '\t';
					break;
				case 'r':
					new_string[j++] = '\r';
					break;
				case 'b':
					new_string[j++] = '\b';
					break;
				case 'f':
					new_string[j++] = '\f';
					break;
				case 'v':
					new_string[j++] = '\v';
					break;
				default:
					new_string[j++] = sv->data[i];
			}
			escape = false;
		} else {
			if (sv->data[i] == '\\') {
				escape = true;
				continue;
			} else if (sv->data[i] == '\"') {
				break;
			}
			new_string[j++] = sv->data[i];
		}
	}
	if (i >= sv->size) {
		fprintf(stderr, "Unclosed string\n");
		exit(1);
	}
	i++;

	new_string[j] = '\0';
	*string = (sv_t) {
		.data = new_string,
		.size = strlen(new_string),
	};

	sv->data += i;
	sv->size -= i;
	return true;
}

bool chop_u64(sv_t *string, uint64_t *value) {
	char *end;
	*value = strtoull(string->data, &end, 0);
	if (end > string->data + string->size) {
		end = string->data + string->size;
	}
	if (end == string->data) {
		return false;
	}
	string->size -= end - string->data;
	string->data = end;
	return true;
}

bool sv_eq(sv_t a, sv_t b) {
	if (a.size != b.size) {
		return false;
	}
	return memcmp(a.data, b.data, a.size) == 0;
}

written_t(elf_header_t) create_elf_header(bb_t *elf) {
	written_t(elf_header_t) written = {0};
	written_init(&written, elf);

	written.data.magic[0] = 0x7f;
	written.data.magic[1] = 'E';
	written.data.magic[2] = 'L';
	written.data.magic[3] = 'F';
	written.data.cls = ELF_CLASS_64;
	written.data.encoding = ELF_ENCODING_LITTLE;
	written.data.object_file_version = 1;
	written.data.abi = ELF_ABI_SYSV;
	written.data.abi_version = 0;
	written.data.type = ELF_TYPE_RELOCATABLE;
	written.data.arch = ELF_ARCH_X86_64;
	written.data.elf_version = 1;
	written.data.entry_address = 0;
	written.data.ph_offset = 0;
	written.data.sh_offset = 0;
	written.data.flags = 0;
	written.data.header_size = sizeof(elf_header_t);
	written.data.ph_entry_size = 0;
	written.data.ph_entry_count = 0;
	written.data.sh_entry_size = sizeof(elf_sh_t);
	written.data.sh_entry_count = 0;
	written.data.sh_shstrtab_index = 0;

	return written;
}

/// @brief Writes a null terminated string to a strtab section.
/// @param section The section to write the string to.
/// @param string The string to write.
/// @return The offset of the written string.
uint32_t section_write_str(section_t *section, sv_t string) {
	assert(section->elf_sh.data.type == SHT_STRTAB && "trying to write a string to a non-strtab section");

	if (section->data->size == 0) {
		bb_add_u8(section->data, 0);
	}
	if (string.size == 0) {
		return 0;
	}

	uint32_t name_offset = section->data->size;

	bb_add(section->data, string.data, string.size);
	bb_add_u8(section->data, 0);

	return name_offset;
}

uint32_t section_write_sym(section_t *symtab, section_t *strtab, sv_t name, uint8_t visibility, uint8_t type, uint16_t section_index, uint64_t address, uint64_t size) {
	uint32_t symbol_index = symtab->data->size / sizeof(elf_symbol_t);

	// Name
	bb_add_u32(symtab->data, section_write_str(strtab, name));

	// Info
	bb_add_u8(symtab->data, (visibility << 4) | type);

	// Other
	bb_add_u8(symtab->data, 0);

	// Section index
	bb_add_u16(symtab->data, section_index);

	// Value
	bb_add_u64(symtab->data, address);

	// Size
	bb_add_u64(symtab->data, size);

	return symbol_index;
}

void section_write_header(section_t *section, bb_t *elf) {
	bb_add(elf, &section->elf_sh, sizeof(section->elf_sh));
}

void section_write_data(section_t *section, bb_t *elf) {
	if (section->elf_sh.data.type == SHT_NULL) {
		return;
	}

	section->elf_sh.data.data_offset = elf->size;
	section->elf_sh.data.data_size = section->data->size;
	bb_add(elf, section->data->data, section->data->size);
}

section_t *section_new(sv_t name, uint32_t type, uint64_t flags) {
	section_t section = {0};
	section.name = name;
	section.data = bb_new();
	assert(section.data != NULL);
	section.elf_sh.data.type = type;
	section.elf_sh.data.flags = flags;

	return heapify(section_t, &section);
}

// todo: allow for overwriting section type in section directive
uint32_t get_section_type(section_t *section) {
	if (sv_eq(section->name, sv_str(".text"))) {
		return SHT_PROGBITS;
	} else if (sv_eq(section->name, sv_str(".data"))) {
		return SHT_PROGBITS;
	} else {
		assert(false && "unimplemented");
	}
}

uint64_t get_section_flags(section_t *section) {
	if (sv_eq(section->name, sv_str(".text"))) {
		return SHF_EXECINSTR | SHF_ALLOC;
	} else if (sv_eq(section->name, sv_str(".data"))) {
		return SHF_WRITE | SHF_ALLOC;
	} else {
		assert(false && "unimplemented");
	}
}

uint64_t get_section_vaddr(section_t *section) {
	if (sv_eq(section->name, sv_str(".text"))) {
		return 0;
	} else if (sv_eq(section->name, sv_str(".data"))) {
		return 0;  // todo: double check that this is ok
	} else {
		assert(false && "unimplemented");
	}
}

uint64_t get_section_align(section_t *section) {
	if (sv_eq(section->name, sv_str(".text"))) {
		return 16;
	} else if (sv_eq(section->name, sv_str(".data"))) {
		return 4; // todo: double check that this is correct
	} else {
		assert(false && "unimplemented");
	}
}

uint64_t get_section_ent_size(section_t *section) {
	if (sv_eq(section->name, sv_str(".text"))) {
		return 0;
	} else if (sv_eq(section->name, sv_str(".data"))) {
		return 0;
	} else {
		assert(false && "unimplemented");
	}
}

symbol_t *find_symbol(sections_t sections, sv_t name) {
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		for (size_t j = 0; j < section->symbols.count; j++) {
			symbol_t *symbol = section->symbols.items[j];
			if (sv_eq(symbol->name, name)) {
				return symbol;
			}
		}
	}

	return NULL;
}

section_t *find_section(sections_t sections, sv_t name) {
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);
		if (sv_eq(section->name, name)) {
			return section;
		}
	}

	return NULL;
}

section_t *find_section_by_elf_index(sections_t *sections, uint32_t index) {
	for (size_t i = 0; i < sections->count; i++) {
		section_t *section = list_at(sections, i);

		if (section->index == index) {
			return section;
		}
	}

	return NULL;
}

sections_t sections_merge(sections_t sections) {
	sections_t merged = {0};

	for (size_t i = 0; i < sections.count; i++) {
		section_t *s = list_at(&sections, i);
		s->merged = false;
	}

	for (size_t i1 = 0; i1 < sections.count; i1++) {
		section_t *s1 = list_at(&sections, i1);
		if (s1->merged) {
			continue;
		}
		s1->merged = true;
		list_push(&merged, s1);

		bb_t *new_data = bb_new();

		for (size_t i2 = 0; i2 < sections.count; i2++) {
			section_t *s2 = list_at(&sections, i2);
			if (!sv_eq(s1->name, s2->name)) {
				continue;
			}
			s2->merged = true;

			bb_add(new_data, s2->data->data, s2->data->size);
		}
	}

	return merged;
}

section_t *sections_push(sections_t *sections, section_t *section) {
	section->index = sections->count;
	return list_push(sections, section);
}

void hexdump(uint8_t *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n%04zu: ", i);
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
}

bb_t *create_elf(sections_t user_sections) {
	user_sections = sections_merge(user_sections);

	sections_t sections = {0};

	// Required sections
	sections_push(&sections, section_new(sv_str(""), SHT_NULL, 0));  // null section
	section_t *shstrtab = sections_push(&sections, section_new(sv_str(".shstrtab"), SHT_STRTAB, 0));
	shstrtab->elf_sh.data.align = 1;

	// Push all user sections to sections list
	for (size_t i = 0; i < user_sections.count; i++) {
		sections_push(&sections, list_at(&user_sections, i));
	}

	// Create symtab and strtab if needed
	bool has_symbols = false;
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		if (section->symbols.count > 0) {
			has_symbols = true;
			break;
		}
	}

	section_t *symtab = NULL;
	if (has_symbols) {
		section_t *strtab = sections_push(&sections, section_new(sv_str(".strtab"), SHT_STRTAB, 0));
		strtab->elf_sh.data.align = 1;

		symtab = sections_push(&sections, section_new(sv_str(".symtab"), SHT_SYMTAB, 0));
		symtab->elf_sh.data.align = 8;
		symtab->elf_sh.data.entry_size = sizeof(elf_symbol_t);
		symtab->elf_sh.data.link = strtab->index;

		section_write_sym(symtab, strtab, sv_str(""), STB_LOCAL, STT_NOTYPE, 0, 0, 0);  // null symbol

		size_t symbol_index = 1;
		for (size_t i = 0; i < sections.count; i++) {
			section_t *section = list_at(&sections, i);

			for (size_t j = 0; j < section->symbols.count; j++) {
				symbol_t *symbol = list_at(&section->symbols, j);
				assert(symbol != NULL);

				written_init(&symbol->elf_symbol, symtab->data);
				symbol->elf_symbol.data.name_offset = section_write_str(strtab, symbol->name);
				symbol->elf_symbol.data.info = STB_GLOBAL << 4 | STT_NOTYPE;
				symbol->elf_symbol.data.other = 0;
				symbol->elf_symbol.data.section_index = section->index;
				symbol->elf_symbol.data.value = symbol->address;
				symbol->elf_symbol.data.size = symbol->size;  // TODO: Nasm always sets size to 0 it seems, look into that

				symbol->index = symbol_index++;

				if (symtab->elf_sh.data.info == 0) {
					symtab->elf_sh.data.info = symbol->index;  // TODO: Set only if this symbol is non-local
				}
			}
		}
	}

	// Create rela sections if needed
	for (size_t i = 0; i < sections.count;i ++) {
		section_t *section = list_at(&sections, i);
		if (section->relocations.count == 0) {
			continue;
		}

		char *buff = malloc(64);
		sprintf(buff, ".rela"sv_fmt, sv_arg(section->name));  // TODO: Bound check

		section_t *rela = sections_push(&sections, section_new(sv_str(buff), SHT_RELA, 0));

		assert(symtab != NULL && "rela relocates symbols, so symtab must exist");
		rela->elf_sh.data.link = symtab->index;
		rela->elf_sh.data.align = 8;
		rela->elf_sh.data.entry_size = sizeof(elf_rela_t);
		rela->elf_sh.data.info = section->index;

		for (size_t j = 0; j < section->relocations.count; j++) {
			relocation_t *relocation = list_at(&section->relocations, j);
			symbol_t *symbol = find_symbol(user_sections, relocation->symbol_name);

			written_init(&relocation->elf_rela, rela->data);
			relocation->elf_rela.data.offset = relocation->patch_offset;
			relocation->elf_rela.data.index_and_type = (symbol->index << 32) | relocation->patch_type;
			relocation->elf_rela.data.addend = relocation->address_offset;
		}
	}

	// TODO: Refactor find_section usage and code i think
	// Sanity checks
	if (!find_section(sections, sv_str(".text"))) {
		fprintf(stderr, "No text section\n");
		exit(1);
	}

	// Put all section names in shstrtab
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		section->elf_sh.data.name_offset = section_write_str(shstrtab, section->name);
	}

	// Write elf file
	bb_t *elf = bb_new();

	// Elf header
	written_t(elf_header_t) elf_header = create_elf_header(elf);

	// Headers
	elf_header.data.sh_offset = elf->size;

	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);
		written_init(&section->elf_sh, elf);
	}

	// Patch
	elf_header.data.sh_entry_count = sections.count;
	elf_header.data.sh_shstrtab_index = shstrtab->index;

	// Update header
	written_update(elf_header);

	// Update symbols and relocations
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		for (size_t j = 0; j < section->symbols.count; j++) {
			symbol_t *symbol = list_at(&section->symbols, j);
			written_update(symbol->elf_symbol);
		}

		for (size_t j = 0; j < section->relocations.count; j++) {
			relocation_t *relocation = list_at(&section->relocations, j);
			written_update(relocation->elf_rela);
		}
	}

	// Write data
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		if (section->elf_sh.data.type == SHT_NULL) {
			assert(section->data->size == 0 && "null section should have no data");
		}

		section->elf_sh.data.data_offset = elf->size;
		section->elf_sh.data.data_size = section->data->size;
		bb_add(elf, section->data->data, section->data->size);
	}

	// Update headers
	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);
		written_update(section->elf_sh);
	}

	return elf;
}

bool startswith_comment(sv_t line) {
	if (line.size == 0) {
		return false;
	}

	return line.data[0] == ';';
}

typedef enum {
	EXPR_REG64,
	EXPR_IMM64,
	EXPR_LABEL,
} expr_type_t;

const char *expr_name(expr_type_t type) {
	switch (type) {
	case EXPR_REG64: return "reg64";
	case EXPR_IMM64: return "imm64";
	case EXPR_LABEL: return "label";
	}
	assert(false && "unreachable");
}

typedef enum {
	RAX,
	RDI,
	RSI,
	RDX,
	RSP,
} reg_t;

typedef struct {
	expr_type_t type;
	union {
		reg_t reg;
		uint64_t imm;
		sv_t label;
	} as;
} expr_t;

expr_t *expr_new(void) {
	expr_t *expr = malloc(sizeof(expr_t));
	assert(expr != NULL);
	memset(expr, 0, sizeof(expr_t));
	return expr;
}

void expr_free(expr_t *expr) {
	free(expr);
}

bool chop_reg64(sv_t *sv, reg_t *reg) {
	if (chop_start(sv, sv_str("rax"))) {
		*reg = RAX;
		return true;
	} else if (chop_start(sv, sv_str("rdi"))) {
		*reg = RDI;
		return true;
	} else if (chop_start(sv, sv_str("rsi"))) {
		*reg = RSI;
		return true;
	} else if (chop_start(sv, sv_str("rdx"))) {
		*reg = RDX;
		return true;
	}

	return false;
}

bool chop_expr(sv_t *sv, expr_t *expr) {
	sv_t orig_sv = *sv;
	*sv = stripped(*sv);

	if (chop_reg64(sv, &expr->as.reg)) {
		expr->type = EXPR_REG64;
		return true;
	} else if (chop_u64(sv, &expr->as.imm)) {
		expr->type = EXPR_IMM64;
		return true;
	} else if (sv->size > 0) {
		// todo: handle label
		// sv_t label_sv = chop_ident(sv);
		// (void)label_sv;
		expr->type = EXPR_IMM64;
		expr->as.imm = -1;
		return true;
	}

	*sv = orig_sv;
	return false;
}

void parse_ret(bb_t *code, sv_t *line) {
	(void)line;
	bb_add_u8(code, 0xc3);
}

void parse_mov(bb_t *code, sv_t *line) {
	expr_t *dest = expr_new();
	if (!chop_expr(line, dest)) {
		fprintf(stderr, "Expected expression\n");
		exit(1);
	}

	if (!chop_start(line, sv_str(","))) {
		fprintf(stderr, "Expected comma\n");
		exit(1);
	}

	expr_t *src = expr_new();
	if (!chop_expr(line, src)) {
		fprintf(stderr, "Expected expression\n");
		exit(1);
	}

	switch (dest->type) {
	case EXPR_REG64: {
		bb_add_u8(code, 0x48);
		switch (dest->as.reg) {
		case RAX: bb_add_u8(code, 0xb8); break;
		case RDX: bb_add_u8(code, 0xba); break;
		case RSI: bb_add_u8(code, 0xbe); break;
		case RDI: bb_add_u8(code, 0xbf); break;
		default: assert(false && "unhandled");
		}
		switch (src->type) {
		case EXPR_IMM64: {
			bb_add_u64(code, src->as.imm);
		} break;
		default: assert(false && "unhandled");
		}
	} break;
	default: assert(false && "unhandled");
	}
}

void strip_and_skip_comment(sv_t *sv) {
	strip(sv);

	if (!startswith_comment(*sv)) {
		return;
	}

	size_t i = 0;
	while (i < sv->size && sv->data[i] != '\n') {
		i++;
	}

	chop_n(sv, i);
}

const char *sv_pos(sv_t sv, size_t i) {
	static char buf[64];

	size_t row = 1;
	size_t col = 1;
	for (size_t j = 0; j < i; j++) {
		if (sv.data[j] == '\n') {
			row++;
			col = 1;
		} else {
			col++;
		}
	}

	sprintf(buf, "%zu:%zu", row, col);  // TODO: Protect against buffer overflow for too big files (col or row too big)
	return buf;
}

typedef enum {
	TK_UNKNOWN,
	TK_EOF,
	TK_IDENT,
	TK_NUMBER,
	TK_COMMA,
	TK_AT,
	TK_LPAR,
	TK_RPAR,
	TK_COLON,
	TK_NEWLINE,
	TK_STRING,
} tk_type_t;

typedef struct {
	sv_t orig_source;
	sv_t source;
	const char *path;
	tk_type_t type;
	union {
		sv_t ident;
		int64_t number;
		sv_t string;
	} as;
} tk_t;

void tk_init(tk_t *tk, const char *source_path, sv_t source) {
	memset(tk, 0, sizeof(tk_t));
	tk->path = source_path;
	tk->orig_source = source;
	tk->source = source;
}

const char *tk_pos(tk_t tk) {
	static char buf[64];

	sprintf(buf, "%s:%s", tk.path, sv_pos(tk.orig_source, tk.orig_source.size - tk.source.size));

	return buf;
}

const char *tk_name(tk_type_t type) {
	switch (type) {
	case TK_AT: return "at symbol";
	case TK_COLON: return "colon";
	case TK_COMMA: return "comma";
	case TK_EOF: return "end of file";
	case TK_IDENT: return "identifier";
	case TK_LPAR: return "left parenthesis";
	case TK_NEWLINE: return "newline";
	case TK_NUMBER: return "number";
	case TK_RPAR: return "right parenthesis";
	case TK_UNKNOWN: return "unknown";
	case TK_STRING: return "string";
	}
	assert(false && "unreachable");
}

bool tk_next(tk_t *tk) {
	strip_and_skip_comment(&tk->source);

	if (tk->source.size == 0) {
		tk->type = TK_EOF;
		return false;
	}

	if (chop_i64(&tk->source, &tk->as.number)) {
		tk->type = TK_NUMBER;
		return true;
	} else if (chop_ident(&tk->source, &tk->as.ident)) {
		tk->type = TK_IDENT;
		return true;
	} else if (chop_string(&tk->source, &tk->as.string)) {
		tk->type = TK_STRING;
		return true;
	} else if (chop_start(&tk->source, sv_str(":"))) {
		tk->type = TK_COLON;
		return true;
	} else if (chop_start(&tk->source, sv_str("\n"))) {
		tk->type = TK_NEWLINE;
		return true;
	} else if (chop_start(&tk->source, sv_str(","))) {
		tk->type = TK_COMMA;
		return true;
	} else if (chop_start(&tk->source, sv_str("@"))) {
		tk->type = TK_AT;
		return true;
	} else if (chop_start(&tk->source, sv_str("("))) {
		tk->type = TK_LPAR;
		return true;
	} else if (chop_start(&tk->source, sv_str(")"))) {
		tk->type = TK_RPAR;
		return true;
	}

	tk->type = TK_UNKNOWN;
	return false;
}

void check_source(const char *source_path, const char *source) {
	tk_t tk;
	tk_init(&tk, source_path, sv_str(source));

	while (tk_next(&tk)) {
	}

	if (tk.type != TK_EOF) {
		printf("%d\n", tk.type);
		fprintf(stderr, "%s: Unexpected character '%c'\n", tk_pos(tk), tk.source.data[0]);
		exit(1);
	}
}

bool parse_reg64(tk_t *tk, reg_t *reg) {
	if (tk->type != TK_IDENT) {
		return false;
	}

	// TODO: Put static assert here so we dont forget to add registers here
	if (sv_eq(tk->as.ident, sv_str("rax"))) {
		*reg = RAX;
		tk_next(tk);
		return true;
	} else if (sv_eq(tk->as.ident, sv_str("rsi"))) {
		*reg = RSI;
		tk_next(tk);
		return true;
	} else if (sv_eq(tk->as.ident, sv_str("rdi"))) {
		*reg = RDI;
		tk_next(tk);
		return true;
	} else if (sv_eq(tk->as.ident, sv_str("rdx"))) {
		*reg = RDX;
		tk_next(tk);
		return true;
	} else if (sv_eq(tk->as.ident, sv_str("rsp"))) {
		*reg = RSP;
		tk_next(tk);
		return true;
	}

	return false;
}

bool parse_label(tk_t *tk, sv_t *label) {
	if (tk->type != TK_IDENT) {
		return false;
	}

	assert(label != NULL);
	*label = tk->as.ident;

	tk_next(tk);
	return true;
}

bool parse_i64(tk_t *tk, uint64_t *value) {
	if (tk->type != TK_NUMBER) {
		return false;
	}

	*value = tk->as.number;
	tk_next(tk);
	return true;
}

bool parse_expr(tk_t *tk, expr_t *expr) {
	if (tk->type == TK_IDENT) {
		if (parse_reg64(tk, &expr->as.reg)) {
			expr->type = EXPR_REG64;
			return true;
		} else if (parse_label(tk, &expr->as.label)) {
			expr->type = EXPR_LABEL;
			return true;
		}
	} else if (tk->type == TK_NUMBER) {
		if (parse_i64(tk, &expr->as.imm)) {
			expr->type = EXPR_IMM64;
			return true;
		}
	}

	return false;
}

bool section_eq(section_t *a, section_t *b) {
	return sv_eq(a->name, b->name);
}

void set_section(section_t **active_section, sections_t *user_sections, sv_t section_name) {
	section_t *section = find_section(*user_sections, section_name);
	if (!section) {
		section = list_push(user_sections, section_new(section_name, SHT_PROGBITS, 0));

		// TODO: Let user set these through section directive
		uint64_t flags = SHF_ALLOC;
		uint64_t align = 0;

		if (sv_eq(section_name, sv_str(".text"))) {
			flags |= SHF_EXECINSTR;
			align = 16;
		} else if (sv_eq(section_name, sv_str(".data"))) {
			flags |= SHF_WRITE;
			align = 4;
		}

		section->elf_sh.data.flags = flags;
		section->elf_sh.data.align = align;
	}

	*active_section = section;
}

void assemble_ret(bb_t *code, relocations_t *relocations, tk_t *tk) {
	(void)relocations;

	bb_add_u8(code, 0xc3);

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "Expected newline after ret instruction\n");
		exit(1);
	}
}

void assemble_syscall(bb_t *code, relocations_t *relocations, tk_t *tk) {
	(void)relocations;

	bb_add_u8(code, 0x0f);
	bb_add_u8(code, 0x05);

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "Expected newline after syscall instruction\n");
		exit(1);
	}
}

void assemble_call(bb_t *code, relocations_t *relocations, tk_t *tk) {

	expr_t *target = expr_new();
	if (!parse_expr(tk, target)) {
		fprintf(stderr, "Expected target operand\n");
		exit(1);
	}

	switch (target->type) {
	case EXPR_LABEL: {
		bb_add_u8(code, 0xe8);

		relocation_t relocation = {
			.patch_offset = bb_add_u32(code, 0),
			.patch_type = R_X86_64_PC32,
			.address_offset = -4,
			.symbol_name = target->as.label,
		};
		list_push(relocations, heapify(relocation_t, &relocation));
	} break;
	default: {
		fprintf(stderr, "Unhandled target type %s\n", expr_name(target->type));
		exit(1);
	} break;
	}

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "Expected newline after call instruction\n");
		exit(1);
	}
}

void assemble_mov(bb_t *code, relocations_t *relocations, tk_t *tk) {
	expr_t *dest = expr_new();
	if (!parse_expr(tk, dest)) {
		fprintf(stderr, "Expected destination operand\n");
		exit(1);
	}

	if (tk->type != TK_COMMA) {
		fprintf(stderr, "%s: Expected comma after destination operand\n", tk_pos(*tk));
		exit(1);
	}
	tk_next(tk);

	expr_t *src = expr_new();
	if (!parse_expr(tk, src)) {
		fprintf(stderr, "Expected source operand\n");
		exit(1);
	}

	switch (dest->type) {
	case EXPR_REG64: {
		bb_add_u8(code, 0x48);
		switch (dest->as.reg) {
		case RAX: bb_add_u8(code, 0xb8); break;
		case RDX: bb_add_u8(code, 0xba); break;
		case RSP: bb_add_u8(code, 0xbc); break;
		case RSI: bb_add_u8(code, 0xbe); break;
		case RDI: bb_add_u8(code, 0xbf); break;
		default: assert(false && "unhandled");
		}
		switch (src->type) {
		case EXPR_IMM64: {
			bb_add_u64(code, src->as.imm);
		} break;
		case EXPR_LABEL: {
			relocation_t relocation = {
				.patch_offset = bb_add_u64(code, 0),
				.patch_type = R_X86_64_64,
				.address_offset = 0,
				.symbol_name = src->as.label,
			};
			list_push(relocations, heapify(relocation_t, &relocation));
		} break;
		default: {
			fprintf(stderr, "Unhandled source type %s\n", expr_name(src->type));
			exit(1);
		} break;
		}
	} break;
	default: {
		fprintf(stderr, "Unhandled dest type %s\n", expr_name(src->type));
		exit(1);
	} break;
	}

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "%s: Expected newline after mov instruction, got %s\n", tk_pos(*tk), tk_name(tk->type));
		exit(1);
	}
}

void assemble_xor(bb_t *code, relocations_t *relocations, tk_t *tk) {
	(void)relocations;

	expr_t *dest = expr_new();
	if (!parse_expr(tk, dest)) {
		fprintf(stderr, "Expected source operand\n");
		exit(1);
	}

	if (tk->type != TK_COMMA) {
		fprintf(stderr, "%s: Expected comma after source operand\n", tk_pos(*tk));
		exit(1);
	}
	tk_next(tk);

	expr_t *src = expr_new();
	if (!parse_expr(tk, src)) {
		fprintf(stderr, "Expected destination operand\n");
		exit(1);
	}

	if (dest->type == EXPR_REG64 && src->type == EXPR_REG64) {
		bb_add_u8(code, 0x48);
		bb_add_u8(code, 0x31);
		if (dest->as.reg == RDI && src->as.reg == RDI) {
			bb_add_u8(code, 0xff);
		} else {
			assert(false && "unhandled");
		}
	} else {
		assert(false && "unhandled");
	}

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "%s: Expected newline after xor instruction, got %s\n", tk_pos(*tk), tk_name(tk->type));
		exit(1);
	}
}

bool try_assemble_label(section_t *active_section, symbols_t *symbols, tk_t *tk) {
	tk_t tk_before = *tk;

	// consume name
	sv_t name = tk->as.ident;
	tk_next(tk);

	if (tk->type != TK_COLON) {
		*tk = tk_before;
		return false;
	}

	// TODO: Check if label exists, run a first pass to get all labels
	symbol_t symbol = {0};
	symbol.name = name;
	symbol.address = active_section->data->size;
	list_push(symbols, heapify(symbol_t, &symbol));

	// consume colon
	tk_next(tk);
	return true;
}

tk_t expect_type(tk_t *tk, tk_type_t type) {
	if (tk->type != type) {
		fprintf(stderr, "%s: Expected '%s'\n", tk_pos(*tk), tk_name(type));
		exit(1);
	}
	tk_t res = *tk;
	tk_next(tk);
	return res;
}

void parse_bytes(bb_t *code, relocations_t *relocations, symbols_t *symbols, tk_t *tk) {
	(void)relocations;
	(void)symbols;

	// consume "bytes"
	tk_next(tk);

	expect_type(tk, TK_LPAR);

	// consume multiple numbers
	while (tk->type != TK_RPAR) {
		if (tk->type != TK_NUMBER) {
			fprintf(stderr, "%s: Expected number after @bytes(\n", tk_pos(*tk));
			exit(1);
		}

		uint64_t value = tk->as.number;
		bb_add_u8(code, value);

		// consume number
		tk_next(tk);

		if (tk->type == TK_COMMA) {
			tk_next(tk);
		} else if (tk->type != TK_RPAR) {
			fprintf(stderr, "%s: Expected ',' or ')' after number\n", tk_pos(*tk));
			exit(1);
		}
	}

	expect_type(tk, TK_RPAR);
}

void parse_ascii(bb_t *code, relocations_t *relocations, symbols_t *symbols, tk_t *tk) {
	(void)relocations;
	(void)symbols;

	// consume "ascii"
	tk_next(tk);

	expect_type(tk, TK_LPAR);

	tk_t string = expect_type(tk, TK_STRING);

	for (size_t i = 0; i < string.as.string.size; i++) {
		bb_add_u8(code, string.as.string.data[i]);
	}

	expect_type(tk, TK_RPAR);
}

void parse_section(section_t **active_section, sections_t *sections, relocations_t *relocations, symbols_t *symbols, tk_t *tk) {
	(void)relocations;
	(void)symbols;

	// consume 'section'
	tk_next(tk);

	expect_type(tk, TK_LPAR);

	sv_t section_name = expect_type(tk, TK_STRING).as.string;

	expect_type(tk, TK_RPAR);

	set_section(active_section, sections, section_name);
}

void parse_directive(section_t **active_section, sections_t *sections, relocations_t *relocations, symbols_t *symbols, tk_t *tk) {
	// consume at
	tk_next(tk);

	if (tk->type != TK_IDENT) {
		fprintf(stderr, "%s: Expected identifier after @\n", tk_pos(*tk));
		exit(1);
	}

	if (sv_eq(tk->as.ident, sv_str("bytes"))) {
		parse_bytes((*active_section)->data, relocations, symbols, tk);
	} else if (sv_eq(tk->as.ident, sv_str("ascii"))) {
		parse_ascii((*active_section)->data, relocations, symbols, tk);
	} else if (sv_eq(tk->as.ident, sv_str("section"))) {
		parse_section(active_section, sections, relocations, symbols, tk);
	} else {
		fprintf(stderr, "%s: Unknown directive '"sv_fmt"'\n", tk_pos(*tk), sv_arg(tk->as.ident));
		exit(1);
	}
}

sections_t assemble(const char *source_path, const char *source_str) {
	sections_t sections = {0};

	section_t *active_section = NULL;
	set_section(&active_section, &sections, sv_str(".text"));

	tk_t tk;
	tk_init(&tk, source_path, sv_str(source_str));
	tk_next(&tk);
	while (true) {
		while (tk.type == TK_NEWLINE) {
			tk_next(&tk);
		}
		if (tk.type == TK_EOF) {
			break;
		}

		if (tk.type == TK_AT) {
			parse_directive(&active_section, &sections, &active_section->relocations, &active_section->symbols, &tk);
			continue;
		}

		if (tk.type != TK_IDENT) {
			fprintf(stderr, "%s: Expected identifier, got %s\n", tk_pos(tk), tk_name(tk.type));
			exit(1);
		}

		const char *start_pos = tk_pos(tk);

		if (try_assemble_label(active_section, &active_section->symbols, &tk)) {
			continue;
		}

		// consume ident
		sv_t ident = tk.as.ident;
		tk_next(&tk);

		// TODO: Error location reporting is just plain wrong for some reason, unexpected tokens also have weird error messages
		bb_t *code = (*active_section).data;
		relocations_t *relocations = &(*active_section).relocations;
		if (sv_eq(ident, sv_str("ret"))) {
			assemble_ret(code, relocations, &tk);
		} else if (sv_eq(ident, sv_str("mov"))) {
			assemble_mov(code, relocations, &tk);
		} else if (sv_eq(ident, sv_str("xor"))) {
			assemble_xor(code, relocations, &tk);
		} else if (sv_eq(ident, sv_str("syscall"))) {
			assemble_syscall(code, relocations, &tk);
		} else if (sv_eq(ident, sv_str("call"))) {
			assemble_call(code, relocations, &tk);
		} else {
			// error, expected a label
			fprintf(stderr, "%s: Expected label or instruction\n", start_pos);
			exit(1);
		}
	}

	return sections;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		print_usage(stderr);
		return 1;
	}

	const char *source_path = argv[1];
	const char *source_str = read_file(source_path);
	assert(source_str != NULL);

	check_source(source_path, source_str);

	// TODO: Implement first pass to get labels
	// list_t *labels = list_new();
	// assert(labels != NULL);

	// get_labels(labels, source_path, source_str);

	// Second pass, assemble instructions
	sections_t sections = assemble(source_path, source_str);

	for (size_t i = 0; i < sections.count; i++) {
		section_t *section = list_at(&sections, i);

		for (size_t j = 0; j < section->symbols.count; j++) {
			symbol_t *symbol = list_at(&section->symbols, j);

			symbol->size = section->data->size - symbol->address;
			if (j > 0) {
				symbol_t *prev_symbol = list_at(&section->symbols, j - 1);
				prev_symbol->size = symbol->address - prev_symbol->address;
			}
		}
	}

	bb_t *elf = create_elf(sections);
	assert(write_file("out.o", elf->data, elf->size));

	list_free(&sections);
	bb_free(elf);
	free((char *)source_str);
	return 0;
}
