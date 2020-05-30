#include <stdio.h>
#include <stdbool.h>
#include "aes.h"
#include "utils.h"

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
		else if (streqi(argv[5], "ofb"))
			AESEncryptOfb(in, out, key, decrypting);
		else if (streqi(argv[5], "ctr"))
			AESEncryptCtr(in, out, key, decrypting);
		else
			fputs("Invalid mode. ECB, CBC, CFB, OFB and CTR are supported.", stderr);

		fclose(in);
		fclose(out);
	}
	else
		fputs("Usage: aes <input file name> <output file name> <key (hex)> <e|d> <mode>", stderr);


	return 0;
}
