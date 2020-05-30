#pragma once
#include <stdio.h>
#include <stdbool.h>

void AESEncryptEcb(FILE *in, FILE *out, unsigned char *key);
void AESDecryptEcb(FILE *in, FILE *out, unsigned char *key);

void AESEncryptCbc(FILE *in, FILE *out, unsigned char *key);
void AESDecryptCbc(FILE *in, FILE *out, unsigned char *key);

void AESEncryptCfb(FILE *in, FILE *out, unsigned char *key);
void AESDecryptCfb(FILE *in, FILE *out, unsigned char *key);

void AESEncryptOfb(FILE *in, FILE *out, unsigned char *key, bool decrypt);

void AESEncryptCtr(FILE *in, FILE *out, unsigned char *key, bool decrypt);
