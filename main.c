#include "rc4.h"
#include <crtdbg.h>

void printcformat(uint8_t *p, size_t sz, char *f, char *pfx) {
	if (pfx)
		printf(pfx);
	for (size_t i = 0; i < sz; i++) {
		printf(f, *p);
		p++;
	}
	puts("");
}


uint8_t *hexstr_to_bytes(uint8_t *s, size_t slen) {
	uint8_t *bytearray;

	bytearray = (uint8_t*)s_malloc((slen / 2));

	for (size_t i = 0; i < slen; i += 2) {
		
		char hex_byte[3] = { s[i], s[i + 1], '\0' };
		bytearray[i / 2] = (unsigned char)strtol(hex_byte, NULL, 16);
	}
	return bytearray;
}

void run_test(uint8_t *key, size_t ksz, uint8_t *raw_data, size_t dsz, uint8_t *expected) {
	uint8_t *crypto_data;
	uint8_t *dec_data;
	uint8_t *raw_expected;

	raw_expected = hexstr_to_bytes(expected, dsz*2);

	crypto_data = wrap_rc4(key, ksz, raw_data, dsz);
	printf("Ciphertext: ");
	printcformat(crypto_data, 10, "%02x", "0x");

	dec_data = wrap_rc4(key, ksz, crypto_data, dsz);
	printf("Decoded: ");
	printcformat(dec_data, 10, "%c", NULL);

	if (!memcmp(dec_data, raw_data, dsz) && !memcmp(raw_expected, crypto_data, dsz))
		puts("Pass");
	else
		puts("Failed");

	puts("============================================================");
	free(dec_data);
	free(crypto_data);
	free(raw_expected);
}

int main(void) {
	//_CrtMemState state;
	//_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
	//
	//_CrtMemCheckpoint(&state);

	puts("============================================================\n"
		"======================== RC4 - Tests =======================\n"
		"============================================================");
	run_test("pacojones", 9, "rc4-crypt", 10, "c194279386ff03b734e4");
	//_CrtMemDumpAllObjectsSince(&state);
}