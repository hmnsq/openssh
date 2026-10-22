/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಶೂನ್ಯ mldsa_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ mlkem_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ ed25519_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ mldsa_eddsa_tests(ಶೂನ್ಯ);

ಸಂರಚನಾ sshbuf *load_text_file(ಧ್ರುವ ವರ್ಣ *name);
ವರ್ಣ *get_json_string(ಸಂರಚನಾ sshbuf *content, ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ consume);

ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *
load_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *ret = ರಿಕ್ತ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ sshbuf *
load_text_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *ret = load_file(name);
	ಧ್ರುವ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	ಪ್ರತಿ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ಯದಿ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ಪ್ರತ್ಯಾಗಮ ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
ವರ್ಣ *
get_json_string(ಸಂರಚನಾ sshbuf *content, ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ consume)
{
	ಸಂರಚನಾ sshbuf *tmp;
	ವರ್ಣ *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ರಿಕ್ತ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", ಕೀಲಿ), 0);
	ಯದಿ (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	ಮುಕ್ತ(k);

	/* Skip colon, spaces, commas */
	ಯಾವತ್ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		ಯದಿ (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), ರಿಕ್ತ);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	ಯದಿ (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
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

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	/* none */
}
