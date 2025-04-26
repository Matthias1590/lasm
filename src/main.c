#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#define SV_FMT "%.*s"
#define SV_ARG(sv) (int)(sv).size, (sv).data

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} bb_t;

bb_t *bb_new(size_t initial_cap) {
	bb_t *bb = malloc(sizeof(bb_t));
	assert(bb != NULL);
	memset(bb, 0, sizeof(bb_t));
	if (initial_cap > 0) {
		bb->capacity = initial_cap;
		bb->data = malloc(initial_cap);
	}
	return bb;
}

void bb_free(bb_t *bb) {
	free(bb->data);
	free(bb);
}

void *bb_add(bb_t *bb, const void *data, size_t size) {
	while (bb->size + size > bb->capacity) {
		bb->capacity = bb->capacity == 0 ? 1 : bb->capacity * 2;
		assert(false && "realloc");
		bb->data = realloc(bb->data, bb->capacity);
		assert(bb->data != NULL);
	}
	memcpy(bb->data + bb->size, data, size);
	bb->size += size;
	return bb->data + bb->size - size;
}

char *bb_add_str(bb_t *bb, const char *str) {
	return bb_add(bb, str, strlen(str));
}

uint8_t *bb_add_u8(bb_t *bb, uint8_t value) {
	return bb_add(bb, &value, sizeof(value));
}

uint16_t *bb_add_u16(bb_t *bb, uint16_t value) {
	return bb_add(bb, &value, sizeof(value));
}

uint32_t *bb_add_u32(bb_t *bb, uint32_t value) {
	return bb_add(bb, &value, sizeof(value));
}

uint64_t *bb_add_u64(bb_t *bb, uint64_t value) {
	return bb_add(bb, &value, sizeof(value));
}

void bb_zeroes(bb_t *bb, size_t count) {
	for (size_t i = 0; i < count; i++) {
		bb_add_u8(bb, 0);
	}
}

typedef struct {
	char *data;
	size_t size;
} sv_t;

typedef struct {
	sv_t name;
	bb_t *bytes;
	uint32_t index;
	uint32_t *name_offset;
	uint64_t *data_offset;
	uint64_t *data_size;
	uint32_t *link;
	uint32_t *info;
	bool rela_created;
} section_t;

void section_free(section_t *section) {
	bb_free(section->bytes);
	free(section);
}

typedef struct {
	sv_t name;
	size_t address;
	size_t end_address;
	size_t symbol_index;
	section_t *section;
} label_t;

typedef struct {
	size_t offset;
	label_t *label;
} patch_t;

typedef struct {
	void **data;
	size_t size;
	size_t capacity;
} list_t;

list_t *list_new(void) {
	list_t *list = malloc(sizeof(list_t));
	assert(list != NULL);
	memset(list, 0, sizeof(list_t));
	return list;
}

void list_push(list_t *list, void *value) {
	if (list->size == list->capacity) {
		list->capacity = list->capacity == 0 ? 1 : list->capacity * 2;
		list->data = realloc(list->data, list->capacity * sizeof(void *));
		assert(list->data != NULL);
	}
	list->data[list->size++] = value;
}

typedef void (*free_func_t)(void *);

/// @brief Frees a list.
/// @param list The list to free.
/// @param free_func The function to use to free each element in the list. If NULL, uses free.
void list_free(list_t *list, free_func_t free_func) {
	if (free_func == NULL) {
		free_func = free;
	}
	for (size_t i = 0; i < list->size; i++) {
		free_func(((void **)list->data)[i]);
	}
	free(list->data);
	free(list);
}

/// @brief Prints usage of the program.
/// @param f The file to print to.
void print_usage(FILE *f) {
	fprintf(f, "Usage: lasm <file>\n");
}

/// @brief Reads an entire file.
/// @param path The path to the file.
/// @return Contents of the file as an owned string.
char *read_file(const char *path) {
	FILE *f = fopen(path, "rb");
	assert(f != NULL);

	assert(fseek(f, 0, SEEK_END) == 0);

	long size = ftell(f);
	assert(size >= 0);

	assert(fseek(f, 0, SEEK_SET) == 0);

	char *buffer = malloc(size + 1);
	assert(buffer != NULL);

	size_t read_size = fread(buffer, 1, size, f);
	assert(read_size == (size_t)size);
	buffer[size] = '\0';

	assert(fclose(f) == 0);
	return buffer;
}

bool write_file(const char *path, const void *data, size_t size) {
	FILE *f = fopen(path, "wb");
	assert(f != NULL);

	size_t written_size = fwrite(data, 1, size, f);
	assert(written_size == size);

	assert(fclose(f) == 0);

	return true;
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

	size_t i = 0;
	while (i < sv->size && sv->data[i] != '"') {
		i++;
	}
	if (i >= sv->size) {
		fprintf(stderr, "Unclosed string\n");
		exit(1);
	}
	i++;

	*string = (sv_t) {
		.data = sv->data,
		.size = i - 1
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

bool label_eq(label_t *a, label_t *b) {
	return sv_eq(a->name, b->name);
}

/// @brief Puts data on the heap.
/// @param data The data to put on the heap.
/// @param size The size of the data.
/// @return A pointer to the data on the heap.
void *heapify(void *data, size_t size) {
	void *ptr = malloc(size);
	assert(ptr != NULL);
	memcpy(ptr, data, size);
	return ptr;
}

typedef bool (*eq_func_t)(const void *, const void *);

void *list_find(list_t *list, void *key, eq_func_t eq) {
	for (size_t i = 0; i < list->size; i++) {
		if (eq(list->data[i], key)) {
			return list->data[i];
		}
	}
	return NULL;
}

#define HEADER_SIZE 64
#define SH_ENT_SIZE 64
#define SYMTAB_ENT_SIZE 24
#define RELA_ENT_SIZE 24
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define STB_GLOBAL 1
#define STT_FUNC 2
#define STT_NOTYPE 0
#define R_X86_64_64 1

void create_elf_header(bb_t *elf, uint64_t **section_header_offset, uint16_t **section_header_entry_count, uint16_t **section_header_shstrtab_index) {
	// Magic
	bb_add_u8(elf, 0x7f);
	bb_add_str(elf, "ELF");

	bb_add_u8(elf, 2); // 64 bit
	bb_add_u8(elf, 1); // Little endian
	bb_add_u8(elf, 1); // Object file format version
	bb_add_u8(elf, 0); // ABI
	bb_add_u8(elf, 0); // ABI version
	assert(elf->size <= 16);
	bb_zeroes(elf, 16 - elf->size); // Padding
	assert(elf->size == 16);
	bb_add_u16(elf, 1); // Relocatable file
	bb_add_u16(elf, 0x3e); // x86_64
	bb_add_u32(elf, 1); // ELF version
	bb_add_u64(elf, 0); // Entry point address
	bb_add_u64(elf, 0); // Program header offset
	*section_header_offset = bb_add_u64(elf, 0); // Section header offset
	bb_add_u32(elf, 0); // Flags
	bb_add_u16(elf, HEADER_SIZE); // Header size
	bb_add_u16(elf, 0); // Program header entry size
	bb_add_u16(elf, 0); // Program header entry count
	bb_add_u16(elf, SH_ENT_SIZE); // Section header entry size
	*section_header_entry_count = bb_add_u16(elf, 0); // Section header entry count
	*section_header_shstrtab_index = bb_add_u16(elf, 0); // Section header string table index
}

void create_elf_section(bb_t *elf, uint16_t *section_header_entry_count,
	uint32_t **name_offset, uint32_t type, uint64_t flags, uint64_t virtual_addr,
	uint64_t **file_offset, uint64_t **size, uint32_t **link, uint32_t **info,
	uint64_t address_align, uint64_t entry_size
) {
	*name_offset = bb_add_u32(elf, 0);
	bb_add_u32(elf, type);
	bb_add_u64(elf, flags);
	bb_add_u64(elf, virtual_addr);
	*file_offset = bb_add_u64(elf, 0);
	*size = bb_add_u64(elf, 0);
	*link = bb_add_u32(elf, 0);
	*info = bb_add_u32(elf, 0);
	bb_add_u64(elf, address_align);
	bb_add_u64(elf, entry_size);
	(*section_header_entry_count)++;
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

section_t *find_section(list_t *sections, sv_t name) {
	for (size_t i = 0; i < sections->size; i++) {
		section_t *section = sections->data[i];
		if (sv_eq(section->name, name)) {
			return section;
		}
	}

	return NULL;
}

section_t *find_section_by_elf_index(list_t *sections, uint32_t index) {
	for (size_t i = 0; i < sections->size; i++) {
		section_t *section = sections->data[i];

		if (section->index == index) {
			return section;
		}
	}

	return NULL;
}

bool is_rela(section_t *section) {
	// TODO: Store type in section and check type here
	return startswith(section->name, sv_str(".rela"));
}

bb_t *create_elf(list_t *sections, list_t *labels, list_t *patches) {
	bb_t *elf = bb_new(4096);

	// ELF header
	uint64_t *section_header_offset;
	uint16_t *section_header_entry_count;
	uint16_t *section_header_shstrtab_index;
	create_elf_header(elf, &section_header_offset, &section_header_entry_count, &section_header_shstrtab_index);

	// Section headers
	*section_header_offset = elf->size;

	void *zero;

	// Null section
	create_elf_section(elf, section_header_entry_count,
		(uint32_t **)&zero,
		SHT_NULL,
		0,
		0,
		(uint64_t **)&zero,
		(uint64_t **)&zero,
		(uint32_t **)&zero,
		(uint32_t **)&zero,
		0,
		0
	);

	// Accumulate sections and create headers
	for (size_t i = 0; i < sections->size; i++) {
		section_t *s = sections->data[i];

		s->rela_created = false;

		if (s->index != 0) {
			continue;
		}

		// Section header
		s->index = *section_header_entry_count;
		create_elf_section(elf, section_header_entry_count,
			&s->name_offset,
			get_section_type(s),
			get_section_flags(s),
			get_section_vaddr(s),
			&s->data_offset,
			&s->data_size,
			&s->link,
			&s->info,
			get_section_align(s),
			get_section_ent_size(s)
		);

		// Section data
		bb_t *data = bb_new(4096);

		for (size_t j = 0; j < sections->size; j++) {
			section_t *section = sections->data[j];
			if (!sv_eq(s->name, section->name)) {
				continue;
			}

			bb_add(data, section->bytes->data, section->bytes->size);
			bb_free(section->bytes);
			section->bytes = NULL;
		}

		s->bytes = data;
	}

	section_t *text = find_section(sections, sv_str(".text"));
	if (!text) {
		fprintf(stderr, "No text section\n");
		exit(1);
	}

	// Symtab section
	uint32_t symtab_index = *section_header_entry_count;

	uint32_t *symtab_name_offset;
	uint64_t *symtab_data_offset;
	uint64_t *symtab_data_size;
	uint32_t *symtab_link;
	create_elf_section(elf, section_header_entry_count,
		&symtab_name_offset,
		SHT_SYMTAB,
		0,
		0,
		&symtab_data_offset,
		&symtab_data_size,
		&symtab_link,
		(uint32_t **)&zero,
		8,
		SYMTAB_ENT_SIZE
	);

	// Strtab section
	uint32_t strtab_index = *section_header_entry_count;

	uint32_t *strtab_name_offset;
	uint64_t *strtab_data_offset;
	uint64_t *strtab_data_size;
	create_elf_section(elf, section_header_entry_count,
		&strtab_name_offset,
		SHT_STRTAB,
		0,
		0,
		&strtab_data_offset,
		&strtab_data_size,
		(uint32_t **)&zero,
		(uint32_t **)&zero,
		1,
		0
	);

	// Create rela sections
	size_t non_rela_sections_count = sections->size;
	for (size_t i = 0; i < non_rela_sections_count; i++) {
		section_t *section = sections->data[i];

		// Create rela if needed
		bool requires_rela = false;
		for (size_t i = 0; i < patches->size; i++) {
			patch_t *patch = patches->data[i];
			label_t *label = patch->label;

			if (sv_eq(label->section->name, section->name)) {
				requires_rela = true;
				break;
			}
		}

		if (!requires_rela || section->rela_created) {
			continue;
		}
		section->rela_created = true;

		char *buf = malloc(64);
		sprintf(buf, ".rela"SV_FMT, SV_ARG(section->name));  // TODO: Bound check

		section_t rela_section = {
			.bytes = bb_new(4096),
			.name = sv_str(buf),
		};

		rela_section.index = *section_header_entry_count;
		create_elf_section(elf, section_header_entry_count,
			&rela_section.name_offset,
			SHT_RELA,
			0,
			0,
			&rela_section.data_offset,
			&rela_section.data_size,
			&rela_section.link,
			&rela_section.info,
			8,
			RELA_ENT_SIZE
		);

		*rela_section.link = symtab_index;
		*rela_section.info = section->index;

		list_push(sections, heapify(&rela_section, sizeof(rela_section)));
	}

	uint32_t text_index = text->index;

	// Shstrtab section
	*section_header_shstrtab_index = *section_header_entry_count;

	uint32_t *shstrtab_name_offset;
	uint64_t *shstrtab_data_offset;
	uint64_t *shstrtab_data_size;
	create_elf_section(elf, section_header_entry_count,
		&shstrtab_name_offset,
		SHT_STRTAB,
		0,
		0,
		&shstrtab_data_offset,
		&shstrtab_data_size,
		(uint32_t **)&zero,
		(uint32_t **)&zero,
		1,
		0
	);

	// Rela sections
	// for (size_t i = 0; i < labels->size; i++) {
	// 	label_t *label = labels->data[i];
	// 	get_or_create_section();

	// 	uint32_t *rela_text_name_offset;
	// 	uint64_t *rela_text_data_offset;
	// 	uint64_t *rela_text_data_size;
	// 	uint32_t *rela_text_link;
	// 	uint32_t *rela_text_info;
	// 	create_elf_section(elf, section_header_entry_count,
	// 		&rela_text_name_offset,
	// 		SHT_RELA,
	// 		0,
	// 		0,
	// 		&rela_text_data_offset,
	// 		&rela_text_data_size,
	// 		&rela_text_link,
	// 		&rela_text_info,
	// 		8,
	// 		RELA_ENT_SIZE
	// 	);
	// }

	// Section data
	//// Shstrtab data
	*shstrtab_data_offset = elf->size;
	bb_add_u8(elf, 0);

	*shstrtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".shstrtab");
	bb_add_u8(elf, 0);

	for (size_t i = 0; i < sections->size; i++) {
		section_t *section = sections->data[i];

		*section->name_offset = elf->size - *shstrtab_data_offset;
		bb_add(elf, section->name.data, section->name.size);
		bb_add_u8(elf, 0);
	}

	*strtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".strtab");
	bb_add_u8(elf, 0);

	*symtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".symtab");
	bb_add_u8(elf, 0);

	// *rela_text_name_offset = elf->size - *shstrtab_data_offset;
	// bb_add_str(elf, ".rela.text");
	// bb_add_u8(elf, 0);

	*shstrtab_data_size = elf->size - *shstrtab_data_offset;

	//// Symtab data
	bb_t *strtab_data = bb_new(4096);
	bb_add_u8(strtab_data, 0);

	*symtab_data_offset = elf->size;
	*symtab_data_size = labels->size * SYMTAB_ENT_SIZE;
	*symtab_link = strtab_index;

	for (size_t i = 0; i < labels->size; i++) {
		label_t *label = labels->data[i];
		assert(label != NULL);

		label->symbol_index = i;

		// Name
		bb_add_u32(elf, strtab_data->size);
		bb_add(strtab_data, label->name.data, label->name.size);
		bb_add_u8(strtab_data, 0);

		// Info
		bb_add_u8(elf, (STB_GLOBAL << 4) | STT_NOTYPE);

		// Other
		bb_add_u8(elf, 0);

		// Section index
		bb_add_u16(elf, text_index);

		// Value
		bb_add_u64(elf, label->address);

		// Size
		bb_add_u64(elf, label->end_address - label->address);
	}

	//// Relas data
	for (size_t i = 0; i < sections->size; i++) {
		section_t *rela_section = sections->data[i];
		if (!is_rela(rela_section)) {
			continue;
		}

		section_t *section = find_section_by_elf_index(sections, *rela_section->info);
		assert(section != NULL);

		rela_section->bytes = bb_new(4096);
		assert(rela_section->bytes != NULL);

		for (size_t j = 0; j < patches->size; j++) {
			patch_t *patch = patches->data[j];
			if (!sv_eq(patch->label->section->name, section->name)) {
				continue;
			}

			bb_add_u64(rela_section->bytes, patch->offset);
			bb_add_u64(rela_section->bytes, (patch->label->symbol_index << 32) | R_X86_64_64);
			bb_add_u64(rela_section->bytes, 0);
		}
	}

	//// Strtab data
	*strtab_data_offset = elf->size;
	*strtab_data_size = strtab_data->size;
	bb_add(elf, strtab_data->data, strtab_data->size);
	bb_free(strtab_data);

	//// Rela.text data
	// *rela_text_link = symtab_index;
	// *rela_text_info = text_index;

	// bb_t *rela_text_data = bb_new(4096);
	// assert(rela_text_data != NULL);

	// for (size_t i = 0; i < patches->size; i++) {
	// 	patch_t *patch = patches->data[i];

	// 	bb_add_u64(rela_text_data, patch->offset);
	// 	bb_add_u64(rela_text_data, (patch->label->symbol_index << 32) | R_X86_64_64);
	// 	bb_add_u64(rela_text_data, 0);
	// }

	// *rela_text_data_offset = elf->size;
	// *rela_text_data_size = rela_text_data->size;
	// bb_add(elf, rela_text_data->data, rela_text_data->size);
	// bb_free(rela_text_data);

	//// Sections
	for (size_t i = 0; i < sections->size; i++) {
		section_t *section = sections->data[i];

		*section->data_size = section->bytes->size;
		*section->data_offset = elf->size;
		bb_add(elf, section->bytes->data, section->bytes->size);
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
} reg_t;

typedef struct {
	expr_type_t type;
	union {
		reg_t reg;
		uint64_t imm;
		label_t *label;
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

void get_labels(list_t *labels, const char *source_path, const char *source_str) {
	label_t label;
	bool was_ident = false;

	tk_t tk;
	tk_init(&tk, source_path, sv_str(source_str));
	while (tk_next(&tk)) {
		if (was_ident && tk.type == TK_COLON) {
			list_push(labels, heapify(&label, sizeof(label)));
		}

		if (tk.type == TK_IDENT) {
			was_ident = true;
			label.name = tk.as.ident;
		} else {
			was_ident = false;
		}
	}
}

bool parse_reg64(tk_t *tk, reg_t *reg) {
	if (tk->type != TK_IDENT) {
		return false;
	}

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
	}

	return false;
}

bool parse_label(tk_t *tk, label_t **label, list_t *labels) {
	if (tk->type != TK_IDENT) {
		return false;
	}

	*label = list_find(labels, &tk->as.ident, (eq_func_t)label_eq);
	assert(label != NULL);

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

bool parse_expr(tk_t *tk, expr_t *expr, list_t *labels) {
	if (tk->type == TK_IDENT) {
		if (parse_reg64(tk, &expr->as.reg)) {
			expr->type = EXPR_REG64;
			return true;
		} else if (parse_label(tk, &expr->as.label, labels)) {
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

void set_section(section_t **active_section, list_t *sections, sv_t section_name) {
	section_t key = {
		.name = section_name,
	};

	section_t *section = list_find(sections, &key, (eq_func_t)section_eq);
	if (!section) {
		section_t sect = {0};
		sect.name = section_name;
		sect.bytes = bb_new(4096);
		assert(sect.bytes != NULL);
		section = heapify(&sect, sizeof(sect));
		list_push(sections, section);
	}

	*active_section = section;
}

void assemble_ret(bb_t *code, list_t *patches, list_t *labels, tk_t *tk) {
	(void)patches;
	(void)labels;

	bb_add_u8(code, 0xc3);

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "Expected newline after ret instruction\n");
		exit(1);
	}
}

void assemble_syscall(bb_t *code, list_t *patches, list_t *labels, tk_t *tk) {
	(void)patches;
	(void)labels;

	bb_add_u8(code, 0x0f);
	bb_add_u8(code, 0x05);

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "Expected newline after syscall instruction\n");
		exit(1);
	}
}

void assemble_mov(bb_t *code, list_t *patches, list_t *labels, tk_t *tk) {
	(void)labels;

	expr_t *dest = expr_new();
	if (!parse_expr(tk, dest, labels)) {
		fprintf(stderr, "Expected source operand\n");
		exit(1);
	}

	if (tk->type != TK_COMMA) {
		fprintf(stderr, "%s: Expected comma after source operand\n", tk_pos(*tk));
		exit(1);
	}
	tk_next(tk);

	expr_t *src = expr_new();
	if (!parse_expr(tk, src, labels)) {
		fprintf(stderr, "Expected destination operand\n");
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
		case EXPR_LABEL: {
			patch_t patch = {
				.offset = code->size,
				.label = src->as.label,
			};
			bb_add_u64(code, 0);
			list_push(patches, heapify(&patch, sizeof(patch)));
		} break;
		default: {
			fprintf(stderr, "Unhandled source type %s\n", expr_name(src->type));
			exit(1);
		} break;
		}
	} break;
	default: assert(false && "unhandled");
	}

	// expect newline
	if (tk->type != TK_NEWLINE) {
		fprintf(stderr, "%s: Expected newline after mov instruction, got %s\n", tk_pos(*tk), tk_name(tk->type));
		exit(1);
	}
}

void assemble_xor(bb_t *code, list_t *patches, list_t *labels, tk_t *tk) {
	(void)patches;
	(void)labels;

	expr_t *dest = expr_new();
	if (!parse_expr(tk, dest, labels)) {
		fprintf(stderr, "Expected source operand\n");
		exit(1);
	}

	if (tk->type != TK_COMMA) {
		fprintf(stderr, "%s: Expected comma after source operand\n", tk_pos(*tk));
		exit(1);
	}
	tk_next(tk);

	expr_t *src = expr_new();
	if (!parse_expr(tk, src, labels)) {
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

bool try_assemble_label(section_t *active_section, list_t *labels, tk_t *tk) {
	tk_t tk_before = *tk;

	// consume name
	sv_t name = tk->as.ident;
	tk_next(tk);

	if (tk->type != TK_COLON) {
		*tk = tk_before;
		return false;
	}

	label_t *label = list_find(labels, &name, (eq_func_t)label_eq);
	assert(label != NULL);

	label->section = active_section;
	label->address = active_section->bytes->size;

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

void parse_bytes(bb_t *code, list_t *patches, list_t *labels, tk_t *tk) {
	(void)patches;
	(void)labels;

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

void parse_section(section_t **active_section, list_t *sections, list_t *patches, list_t *labels, tk_t *tk) {
	(void)patches;
	(void)labels;

	// consume 'section'
	tk_next(tk);

	expect_type(tk, TK_LPAR);

	sv_t section_name = expect_type(tk, TK_STRING).as.string;

	expect_type(tk, TK_RPAR);

	set_section(active_section, sections, section_name);
}

void parse_directive(section_t **active_section, list_t *sections, list_t *patches, list_t *labels, tk_t *tk) {
	// consume at
	tk_next(tk);

	if (tk->type != TK_IDENT) {
		fprintf(stderr, "%s: Expected identifier after @\n", tk_pos(*tk));
		exit(1);
	}

	if (sv_eq(tk->as.ident, sv_str("bytes"))) {
		parse_bytes((*active_section)->bytes, patches, labels, tk);
	} else if (sv_eq(tk->as.ident, sv_str("section"))) {
		parse_section(active_section, sections, patches, labels, tk);
	} else {
		fprintf(stderr, "%s: Unknown directive '"SV_FMT"'\n", tk_pos(*tk), SV_ARG(tk->as.ident));
		exit(1);
	}
}

list_t *assemble(list_t *patches, list_t *labels, const char *source_path, const char *source_str) {
	list_t *sections = list_new();
	assert(sections != NULL);

	section_t *active_section = NULL;
	set_section(&active_section, sections, sv_str(".text"));

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
			parse_directive(&active_section, sections, patches, labels, &tk);
			continue;
		}

		if (tk.type != TK_IDENT) {
			fprintf(stderr, "%s: Expected identifier, got %s\n", tk_pos(tk), tk_name(tk.type));
			exit(1);
		}

		const char *start_pos = tk_pos(tk);

		if (try_assemble_label(active_section, labels, &tk)) {
			continue;
		}

		// consume ident
		sv_t ident = tk.as.ident;
		tk_next(&tk);

		bb_t *code = (*active_section).bytes;
		if (sv_eq(ident, sv_str("ret"))) {
			assemble_ret(code, patches, labels, &tk);
		} else if (sv_eq(ident, sv_str("mov"))) {
			assemble_mov(code, patches, labels, &tk);
		} else if (sv_eq(ident, sv_str("xor"))) {
			assemble_xor(code, patches, labels, &tk);
		} else if (sv_eq(ident, sv_str("syscall"))) {
			assemble_syscall(code, patches, labels, &tk);
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

	list_t *labels = list_new();
	assert(labels != NULL);

	get_labels(labels, source_path, source_str);

	// Second pass, assemble instructions
	list_t *patches = list_new();
	assert(patches != NULL);

	list_t *sections = assemble(patches, labels, source_path, source_str);
	assert(sections != NULL);

	// Apply patches
	// for (size_t i = 0; i < patches->size; i++) {
	// 	patch_t *patch = patches->data[i];
	// 	*patch->value = patch->label->address;
	// }

	for (size_t i = 0; i < labels->size; i++) {
		label_t *label = labels->data[i];
		assert(label != NULL);
		label->end_address = label->section->bytes->size;
		if (i > 0) {
			((label_t *)labels->data[i - 1])->end_address = label->address;
		}
	}

	bb_t *elf = create_elf(sections, labels, patches);
	assert(write_file("out.o", elf->data, elf->size));

	list_free(labels, NULL);
	list_free(sections, (free_func_t)section_free);
	bb_free(elf);
	free((char *)source_str);
	return 0;
}
