#pragma once
#include <stdbool.h>

unsigned char gmul(unsigned char a, unsigned char b);
void fillRandom128(void *dst);
bool streqi(const char *s1, const char *s2);
bool parseKey(const char *hexString, unsigned char key[16]);
void xor128(void *dst, const void *src); //defined in resource.asm