/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"
#அந்தர்பாவ "sshbuf.h"

வெறுமை mldsa_tests(வெறுமை);
வெறுமை mlkem_tests(வெறுமை);
வெறுமை ed25519_tests(வெறுமை);
வெறுமை mldsa_eddsa_tests(வெறுமை);

கட்டமைப்பு sshbuf *load_text_file(மாறிலி எழுத்து *name);
எழுத்து *get_json_string(கட்டமைப்பு sshbuf *content, மாறிலி எழுத்து *சாவி, முழு consume);

நிலையான கட்டமைப்பு sshbuf *
load_file(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *ret = வெற்று;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, வெற்று);
	திரும்பு ret;
}

கட்டமைப்பு sshbuf *
load_text_file(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *ret = load_file(name);
	மாறிலி u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	க்கு (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		எனில் (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		இல்லையெனில்
			நிறுத்து;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	திரும்பு ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
எழுத்து *
get_json_string(கட்டமைப்பு sshbuf *content, மாறிலி எழுத்து *சாவி, முழு consume)
{
	கட்டமைப்பு sshbuf *tmp;
	எழுத்து *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, வெற்று);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", சாவி), 0);
	எனில் (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	விடுவி(k);

	/* Skip colon, spaces, commas */
	போது (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		எனில் (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		இல்லையெனில்
			நிறுத்து;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), வெற்று);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	எனில் (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	திரும்பு ret;
}

வெறுமை
tests(வெறுமை)
{
#ifdef USE_MLDSA
	mldsa_tests();
#endif
#ifdef USE_MLKEM768X25519
	mlkem_tests();
#endif
	ed25519_tests();
#ifdef USE_MLDSA
	mldsa_eddsa_tests();
#endif
}

வெறுமை
benchmarks(வெறுமை)
{
	/* none */
}
