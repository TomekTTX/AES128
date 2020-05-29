#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Multiply two bytes over GF(256)
unsigned char gmul(unsigned char a, unsigned char b) {
	unsigned char ret = 0;

	while (a && b) {
		if (b & 1)
			ret ^= a;

		a = (a & 0x80 ? (a << 1) ^ 0x11B : a << 1);

		b >>= 1;
	}

	return ret;
}

// Generate 128 pseudo-random bits into dst
void fillRandom128(void *dst) {
	srand((unsigned int)time(NULL));

	for (short i = 0; i < 16; ++i) {
		((unsigned char *)dst)[i] = (unsigned char)rand();
	}
}

// Check for equal strings (case-insensitive)
bool streqi(const char *s1, const char *s2) {
	return _strcmpi(s1, s2) == 0;
}

// Convert hex string to key bytes
bool parseKey(const char *hexString, unsigned char key[16]) {
	char byteBuf[2];
	size_t len = strlen(hexString);

	memset(key, 0, 16);

	for (short i = 15; i >= 0; --i) {
		if (len >= 2) {
			memmove(byteBuf, hexString + len - 2, 2);
			if (sscanf_s(byteBuf, "%2hhx", key + i) <= 0)
				return false;
			len -= 2;
		}
		else if (len == 1) {
			byteBuf[1] = hexString[0];
			byteBuf[0] = '0';
			if (sscanf_s(byteBuf, "%2hhx", key + i) <= 0)
				return false;
			len -= 1;
		}
		else break;
	}

	return true;
}