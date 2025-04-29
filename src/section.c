#include "section.h"
#include "list.h"

void section_free(section_t *section) {
	bb_free(section->data);
	list_free(&section->symbols);
	list_free(&section->relocations);
	free(section);
}
