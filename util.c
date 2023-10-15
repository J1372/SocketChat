#include "util.h"
#include <string.h>

int fgets_no_newline(char* store, int store_size, FILE* stream)
{
	fgets(store, store_size, stream);
	
	int length_no_newline = strnlen(store, store_size);
	if (length_no_newline > 0 && store[length_no_newline - 1] == '\n')
	{
		--length_no_newline;
		store[length_no_newline] = '\0';
	}
	
	return length_no_newline;
}

int prompt_yes(const char* msg)
{
	char buf[5];
	puts(msg);
	fgets(buf, 5, stdin);
	return buf[0] == 'y';
}

int prompt_string(const char* msg, char* store, int store_size)
{
	puts(msg);
	return fgets_no_newline(store, store_size, stdin);
}
