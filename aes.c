#include "aes.h"
#include "aes_modules.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

void AESEncryptEcb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fwrite(&blockCount, sizeof(blockCount), 2, out);

	while ((lastBlockSize = fread(buffer, 1, 16, in)) == 16) {
		encryptBlock(buffer, keys);
		fwrite(buffer, 1, 16, out);
		++blockCount;
	}

	if (lastBlockSize != 0) {
		memset(buffer + lastBlockSize, 0, 16 - lastBlockSize);
		encryptBlock(buffer, keys);
		fwrite(buffer, 1, 16, out);
	}

	fseek(out, 0, SEEK_SET);
	fwrite(&blockCount, sizeof(blockCount), 1, out);
	fwrite(&lastBlockSize, sizeof(lastBlockSize), 1, out);
}

void AESDecryptEcb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], keys[11][16];
	size_t blockCount, lastBlockSize;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fread(&blockCount, sizeof(blockCount), 1, in);
	fread(&lastBlockSize, sizeof(lastBlockSize), 1, in);

	while (blockCount --> 0) {
		fread(buffer, 1, 16, in);
		decryptBlock(buffer, keys);
		fwrite(buffer, 1, 16, out);
	}

	if (lastBlockSize != 0) {
		fread(buffer, 1, 16, in);
		decryptBlock(buffer, keys);
		fwrite(buffer, 1, lastBlockSize, out);
	}
}

void AESEncryptCbc(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], prevBuffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fwrite(&blockCount, sizeof(blockCount), 2, out);
	fillRandom128(prevBuffer);
	fwrite(prevBuffer, 1, 16, out);

	while ((lastBlockSize = fread(buffer, 1, 16, in)) == 16) {
		xor128(buffer, prevBuffer);
		encryptBlock(buffer, keys);
		fwrite(buffer, 1, 16, out);
		memmove(prevBuffer, buffer, 16);
		++blockCount;
	}

	if (lastBlockSize != 0) {
		memset(buffer + lastBlockSize, 0, 16 - lastBlockSize);
		xor128(buffer, prevBuffer);
		encryptBlock(buffer, keys);
		fwrite(buffer, 1, 16, out);
	}

	fseek(out, 0, SEEK_SET);
	fwrite(&blockCount, sizeof(blockCount), 1, out);
	fwrite(&lastBlockSize, sizeof(lastBlockSize), 1, out);
}

void AESDecryptCbc(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], prevBuffer[16], sideBuffer[16], keys[11][16];
	size_t blockCount, lastBlockSize;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fread(&blockCount, sizeof(blockCount), 1, in);
	fread(&lastBlockSize, sizeof(lastBlockSize), 1, in);
	fread(prevBuffer, 1, 16, in);

	while (blockCount-- > 0) {
		fread(buffer, 1, 16, in);
		memcpy(sideBuffer, buffer, 16);
		decryptBlock(buffer, keys);
		xor128(buffer, prevBuffer);
		fwrite(buffer, 1, 16, out);
		memmove(prevBuffer, sideBuffer, 16);
	}

	if (lastBlockSize != 0) {
		fread(buffer, 1, 16, in);
		decryptBlock(buffer, keys);
		xor128(buffer, prevBuffer);
		fwrite(buffer, 1, lastBlockSize, out);
	}
}

void AESEncryptCfb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], sideBuffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fwrite(&blockCount, sizeof(blockCount), 2, out);
	fillRandom128(sideBuffer);
	fwrite(sideBuffer, 1, 16, out);

	while ((lastBlockSize = fread(buffer, 1, 16, in)) == 16) {
		encryptBlock(sideBuffer, keys);
		xor128(sideBuffer, buffer);
		fwrite(sideBuffer, 1, 16, out);
		++blockCount;
	}

	if (lastBlockSize != 0) {
		memset(buffer + lastBlockSize, 0, 16 - lastBlockSize);
		encryptBlock(sideBuffer, keys);
		xor128(sideBuffer, buffer);
		fwrite(sideBuffer, 1, 16, out);
	}

	fseek(out, 0, SEEK_SET);
	fwrite(&blockCount, sizeof(blockCount), 1, out);
	fwrite(&lastBlockSize, sizeof(lastBlockSize), 1, out);
}

void AESDecryptCfb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], sideBuffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fread(&blockCount, sizeof(blockCount), 1, in);
	fread(&lastBlockSize, sizeof(lastBlockSize), 1, in);
	fread(sideBuffer, 1, 16, in);

	while (blockCount --> 0) {
		fread(buffer, 1, 16, in);
		encryptBlock(sideBuffer, keys);
		xor128(sideBuffer, buffer);
		fwrite(sideBuffer, 1, 16, out);
		memmove(sideBuffer, buffer, 16);
	}

	if (lastBlockSize != 0) {
		fread(buffer, 1, 16, in);
		encryptBlock(sideBuffer, keys);
		xor128(sideBuffer, buffer);
		fwrite(sideBuffer, 1, lastBlockSize, out);
	}
}

void AESEncryptOfb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], sideBuffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fwrite(&blockCount, sizeof(blockCount), 2, out);
	fillRandom128(sideBuffer);
	fwrite(sideBuffer, 1, 16, out);

	while ((lastBlockSize = fread(buffer, 1, 16, in)) == 16) {
		encryptBlock(sideBuffer, keys);
		xor128(buffer, sideBuffer);
		fwrite(buffer, 1, 16, out);
		++blockCount;
	}

	if (lastBlockSize != 0) {
		memset(buffer + lastBlockSize, 0, 16 - lastBlockSize);
		encryptBlock(sideBuffer, keys);
		xor128(buffer, sideBuffer);
		fwrite(buffer, 1, 16, out);
	}

	fseek(out, 0, SEEK_SET);
	fwrite(&blockCount, sizeof(blockCount), 1, out);
	fwrite(&lastBlockSize, sizeof(lastBlockSize), 1, out);
}

void AESDecryptOfb(FILE *in, FILE *out, unsigned char *key) {
	unsigned char buffer[16], sideBuffer[16], keys[11][16];
	size_t blockCount = 0, lastBlockSize = 0;

	keySchedule((unsigned int *)key, (unsigned int *)keys);

	fread(&blockCount, sizeof(blockCount), 1, in);
	fread(&lastBlockSize, sizeof(lastBlockSize), 1, in);
	fread(sideBuffer, 1, 16, in);

	while (blockCount-- > 0) {
		fread(buffer, 1, 16, in);
		encryptBlock(sideBuffer, keys);
		xor128(buffer, sideBuffer);
		fwrite(buffer, 1, 16, out);
	}

	if (lastBlockSize != 0) {
		fread(buffer, 1, 16, in);
		encryptBlock(sideBuffer, keys);
		xor128(buffer, sideBuffer);
		fwrite(buffer, 1, lastBlockSize, out);
	}
}

