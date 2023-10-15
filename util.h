#ifndef MESSAGER_UTIL_H
#define MESSAGER_UTIL_H

#include <stdio.h>

int fgets_no_newline(char* store, int store_size, FILE* stream);

int prompt_yes(const char* msg);
int prompt_string(const char* msg, char* store, int store_size);


#endif
