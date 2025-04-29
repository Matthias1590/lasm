#pragma once

#include <stdlib.h>

#define sv_fmt "%.*s"
#define sv_arg(sv) (int)(sv).size, (sv).data

typedef struct {
	char *data;
	size_t size;
} sv_t;
