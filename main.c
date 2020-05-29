#include <stdio.h>
#include <stdbool.h>
#include "aes.h"
#include "utils.h"

#define TEST_FILE "test.txt"
#define TEST_FILE_OUT "test.dat"
#define TEST_FILE_DEC "dectest.txt"


int main(int argc, char **argv) {
	unsigned char key[16], mode;
	bool decrypting;
	FILE *in = NULL, *out = NULL;

	if (argc == 6) {

		//Process command line arguments
		mode = argv[4][0];
		if (mode == 'd')
			decrypting = true;
		else if (mode == 'e')
			decrypting = false;
		else {
			fputs("Invalid token. Specify 'e' for encrypting or 'd' for decrypting.", stderr);
			return 1;
		}
		if (!parseKey(argv[3], key)) {
			fputs("Key parsing failed.", stderr);
			return 1;
		}
		if (fopen_s(&in, argv[1], "rb") != 0) {
			fprintf_s(stderr, "File '%s' could not be opened.\n", argv[1]);
			return 1;
		}
		if (fopen_s(&out, argv[2], "wb") != 0) {
			fclose(in);
			fprintf_s(stderr, "File '%s' could not be opened.\n", argv[2]);
			return 1;
		}
		
		// Check encryption mode and perform selected action
		if (streqi(argv[5], "ecb"))
			decrypting ? AESDecryptEcb(in, out, key) : AESEncryptEcb(in, out, key);
		else if (streqi(argv[5], "cbc"))
			decrypting ? AESDecryptCbc(in, out, key) : AESEncryptCbc(in, out, key);
		else if (streqi(argv[5], "cfb"))
			decrypting ? AESDecryptCfb(in, out, key) : AESEncryptCfb(in, out, key);
		else
			fputs("Invalid mode. ECB, CBC and CFB are supported.", stderr);

		fclose(in);
		fclose(out);
	}
	else
		fputs("Usage: aes <input file name> <output file name> <key (hex)> <e|d> <mode>", stderr);


	return 0;
}

/*
	unsigned char key[16] = "0123456789ABCDEF";

	FILE *f1, *f2, *f3;

	fopen_s(&f1, TEST_FILE, "r");
	fopen_s(&f2, TEST_FILE_OUT, "wb");

	AESEncryptCfb(f1, f2, key);

	fclose(f1);
	freopen_s(&f2, TEST_FILE_OUT, "rb", f2);
	fopen_s(&f3, TEST_FILE_DEC, "w");

	AESDecryptCfb(f2, f3, key);

	fclose(f2);
	fclose(f3);
*/

//unsigned char key[] = "abcdefghijklmnop";

//unsigned char a[] = "0123456789ABCDEF";
//
//AES_Encrypt(a, 16, key);
//AES_Decrypt(a, 16, key);

//if (argc < 2) {
//	puts("Please specify file name.");
//	return 1;
//}