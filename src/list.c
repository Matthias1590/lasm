#include "list.h"
#include <stdlib.h>

void _list_free(void ***items, size_t *count, size_t *capacity) {
	free(*items);
	*items = NULL;
	*count = 0;
	*capacity = 0;
}

void *_list_push(void ***items, size_t *count, size_t *capacity, void *item) {
	if (*count == *capacity) {
		*capacity = *capacity == 0 ? 1 : *capacity * 2;
		*items = realloc(*items, *capacity * sizeof(void *));
	}
	(*items)[*count] = item;
	(*count)++;
	return item;
}

void *_list_at(void **items, size_t count, size_t i) {
	if (i >= count) {
		return NULL;
	}
	return items[i];
}
