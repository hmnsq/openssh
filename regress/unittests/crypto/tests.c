/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "../test_helper/test_helper.h"
#অন্তর্ভাৱ "sshbuf.h"

শূন্য mldsa_tests(শূন্য);
শূন্য mlkem_tests(শূন্য);
শূন্য ed25519_tests(শূন্য);
শূন্য mldsa_eddsa_tests(শূন্য);

সংরচনা sshbuf *load_text_file(ধ্রুৱ ৱর্ণ *name);
ৱর্ণ *get_json_string(সংরচনা sshbuf *content, ধ্রুৱ ৱর্ণ *চাবি, পূর্ণাঙ্ক consume);

স্থির সংরচনা sshbuf *
load_file(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *ret = রিক্ত;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, রিক্ত);
	ঘূৰাই ret;
}

সংরচনা sshbuf *
load_text_file(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *ret = load_file(name);
	ধ্রুৱ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	বাবে (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		যদি (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		অন্যথা
			ভঙ্গ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ঘূৰাই ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
ৱর্ণ *
get_json_string(সংরচনা sshbuf *content, ধ্রুৱ ৱর্ণ *চাবি, পূর্ণাঙ্ক consume)
{
	সংরচনা sshbuf *tmp;
	ৱর্ণ *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, রিক্ত);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", চাবি), 0);
	যদি (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	মুক্ত(k);

	/* Skip colon, spaces, commas */
	যেতিয়ালৈ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		যদি (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		অন্যথা
			ভঙ্গ;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), রিক্ত);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	যদি (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ঘূৰাই ret;
}

শূন্য
tests(শূন্য)
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

শূন্য
benchmarks(শূন্য)
{
	/* none */
}
