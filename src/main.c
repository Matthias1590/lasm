#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} bb_t;

bb_t *bb_new(void) {
	bb_t *bb = malloc(sizeof(bb_t));
	assert(bb != NULL);
	memset(bb, 0, sizeof(bb_t));
	return bb;
}

void bb_free(bb_t *bb) {
	free(bb->data);
	free(bb);
}

void *bb_add(bb_t *bb, const void *data, size_t size) {
	if (bb->size + size > bb->capacity) {
		bb->capacity = bb->capacity == 0 ? 1 : bb->capacity * 2;
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

typedef struct{
	sv_t name;
	size_t address;
	size_t end_address;
} label_t;

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

/// @brief Frees a list.
/// @param list The list to free.
/// @param free_func The function to use to free each element in the list. If NULL, uses free.
void list_free(list_t *list, void (*free_func)(void *)) {
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

/// @brief Chops a token from the string.
/// @param string The string to chop from.
/// @param delim A string containing delimiter characters.
/// @return The chopped token.
sv_t chop_until(sv_t *string, const char *delim) {
	char *end = strpbrk(string->data, delim);
	if (end == NULL || end >= (char *)string->data + string->size) {
		end = (char *)string->data + string->size;
	}

	// TODO: Make sure this isnt an off by one error
	size_t line_size = end - (char *)string->data;
	sv_t line = { .data = string->data, .size = line_size };
	string->data = (char *)string->data + line_size + 1;
	string->size -= line_size + 1;
	return line;
}

/// @brief Strips leading and trailing whitespace from a string.
/// @param string The string to strip.
/// @return The stripped string.
sv_t stripped(sv_t string) {
	while (string.size > 0 && isspace(string.data[0])) {
		string.data++;
		string.size--;
	}
	while (string.size > 0 && isspace(string.data[string.size - 1])) {
		string.size--;
	}
	return string;
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

bool get_u64(sv_t string, uint64_t *value) {
	char *end;
	*value = strtoull(string.data, &end, 0);
	if (end == string.data) {
		return false;
	}
	return true;
}

sv_t sv_lit(const char *str) {
	return (sv_t) {
		.data = (char *)str,
		.size = strlen(str),
	};
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
	uint64_t **file_offset, uint64_t **size, uint32_t **link, uint32_t info,
	uint64_t address_align, uint64_t entry_size
) {
	*name_offset = bb_add_u32(elf, 0);
	bb_add_u32(elf, type);
	bb_add_u64(elf, flags);
	bb_add_u64(elf, virtual_addr);
	*file_offset = bb_add_u64(elf, 0);
	*size = bb_add_u64(elf, 0);
	*link = bb_add_u32(elf, 0);
	bb_add_u32(elf, info);
	bb_add_u64(elf, address_align);
	bb_add_u64(elf, entry_size);
	(*section_header_entry_count)++;
}

bb_t *create_elf(bb_t *code, list_t *exports) {
	bb_t *elf = bb_new();

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
		0,
		0,
		0
	);

	// Text section
	uint32_t text_index = *section_header_entry_count;

	uint32_t *text_name_offset;
	uint64_t *text_data_offset;
	uint64_t *text_data_size;
	create_elf_section(elf, section_header_entry_count,
		&text_name_offset,
		SHT_PROGBITS,
		SHF_EXECINSTR | SHF_ALLOC,
		0,
		&text_data_offset,
		&text_data_size,
		(uint32_t **)&zero,
		0,
		16,
		0
	);

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
		0,
		1,
		0
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
		0,
		1,
		0
	);

	// Symtab section
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
		0,
		8,
		SYMTAB_ENT_SIZE
	);

	// Section data
	//// Text data
	*text_data_offset = elf->size;
	*text_data_size = code->size;
	bb_add(elf, code->data, code->size);

	//// Shstrtab data
	*shstrtab_data_offset = elf->size;
	bb_add_u8(elf, 0);

	*shstrtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".shstrtab");
	bb_add_u8(elf, 0);

	*text_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".text");
	bb_add_u8(elf, 0);

	*strtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".strtab");
	bb_add_u8(elf, 0);

	*symtab_name_offset = elf->size - *shstrtab_data_offset;
	bb_add_str(elf, ".symtab");
	bb_add_u8(elf, 0);

	*shstrtab_data_size = elf->size - *shstrtab_data_offset;

	//// Symtab data
	bb_t *strtab_data = bb_new();
	bb_add_u8(strtab_data, 0);

	*symtab_data_offset = elf->size;
	*symtab_data_size = exports->size * SYMTAB_ENT_SIZE;
	*symtab_link = strtab_index;

	for (size_t i = 0; i < exports->size; i++) {
		label_t *label = exports->data[i];
		assert(label != NULL);

		// Name
		bb_add_u32(elf, strtab_data->size);
		bb_add(strtab_data, label->name.data, label->name.size);
		bb_add_u8(strtab_data, 0);

		// Info
		bb_add_u8(elf, (STB_GLOBAL << 4) | STT_FUNC);

		// Other
		bb_add_u8(elf, 0);

		// Section index
		bb_add_u16(elf, text_index);

		// Value
		bb_add_u64(elf, label->address);

		// Size
		bb_add_u64(elf, label->end_address - label->address);
	}

	//// Strtab data
	*strtab_data_offset = elf->size;
	*strtab_data_size = strtab_data->size;
	bb_add(elf, strtab_data->data, strtab_data->size);

	bb_free(strtab_data);
	return elf;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		print_usage(stderr);
		return 1;
	}

	char *source_str = read_file(argv[1]);
	assert(source_str != NULL);

	list_t *labels = list_new();

	// First pass, find all labels
	sv_t source = { .data = source_str, .size = strlen(source_str) };
	while (true) {
		sv_t line = chop_until(&source, "\n");
		if (line.size == 0) {
			break;
		}

		line = stripped(line);
		if (line.size == 0 || line.data[0] == '#') {
			continue;
		}

		sv_t label_name;
		if (!get_label_name(line, &label_name)) {
			// Skip non-label lines
			continue;
		}

		label_t label = {
			.name = label_name,
			.address = 0,
			.end_address = 0,
		};
		list_push(labels, heapify(&label, sizeof(label_t)));
	}

	// Second pass, assemble instructions
	bb_t *code = bb_new();

	source = (sv_t){ .data = source_str, .size = strlen(source_str) };
	while (true) {
		sv_t line = chop_until(&source, "\n");
		if (line.size == 0) {
			break;
		}

		line = stripped(line);
		if (line.size == 0 || line.data[0] == '#') {
			continue;
		}

		sv_t label_name;
		if (get_label_name(line, &label_name)) {
			label_t *label = list_find(labels, &label_name, (eq_func_t)label_eq);
			assert(label != NULL);

			label->address = code->size;
			label->end_address = code->size + 1;
			continue;
		}

		sv_t opcode = stripped(chop_until(&line, ", "));
		assert(opcode.size > 0);

		if (sv_eq(opcode, sv_lit("ret"))) {
			bb_add_u8(code, 0xc3);
		} else if (sv_eq(opcode, sv_lit("mov"))) {
			sv_t dest_sv = stripped(chop_until(&line, ", "));
			if (!sv_eq(dest_sv, sv_lit("rax"))) {
				assert(false && "Not implemented");
			}
			
			sv_t src_sv = stripped(line);
			uint64_t src = 0;
			if (!get_u64(src_sv, &src)) {
				assert(false && "Not implemented");
			}

			bb_add_u8(code, 0x48);
			bb_add_u8(code, 0xb8);
			bb_add_u64(code, src);
		} else {
			fprintf(stderr, "Unrecognized opcode: '%.*s'\n", (int)opcode.size, opcode.data);
		}
	}

	bb_t *elf = create_elf(code, labels);
	assert(write_file("out.o", elf->data, elf->size));

	list_free(labels, NULL);
	bb_free(code);
	bb_free(elf);
	free(source_str);
	return 0;
}
