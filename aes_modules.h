#pragma once

void keySchedule(unsigned int *key, unsigned int *schedule);

void addRoundKey(unsigned char *data, const unsigned char *key);

void subBytes(unsigned char *data, int count);
void subBytesReverse(unsigned char *data, int count);

void shiftRows(void *);			//defined in resource.asm
void shiftRowsReverse(void *);	//defined in resource.asm

void mixColumns(unsigned char *block);
void mixColumnsReverse(unsigned char *block);

void encryptBlock(unsigned char *block, const unsigned char keys[11][16]);
void decryptBlock(unsigned char *block, const unsigned char keys[11][16]);
