/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

ଶୂନ୍ୟ mldsa_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ mlkem_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ ed25519_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ mldsa_eddsa_tests(ଶୂନ୍ୟ);

ସଂରଚନା sshbuf *load_text_file(ଅଚଳ ଅକ୍ଷର *name);
ଅକ୍ଷର *get_json_string(ସଂରଚନା sshbuf *content, ଅଚଳ ଅକ୍ଷର *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା consume);

ସ୍ଥିର ସଂରଚନା sshbuf *
load_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *ret = ଖାଲି;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ଖାଲି);
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା sshbuf *
load_text_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *ret = load_file(name);
	ଅଚଳ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	ପାଇଁ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ଯଦି (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ଫେରନ୍ତୁ ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
ଅକ୍ଷର *
get_json_string(ସଂରଚନା sshbuf *content, ଅଚଳ ଅକ୍ଷର *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା consume)
{
	ସଂରଚନା sshbuf *tmp;
	ଅକ୍ଷର *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ଖାଲି);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", ଚାବି), 0);
	ଯଦି (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	ମୁକ୍ତ(k);

	/* Skip colon, spaces, commas */
	ଯେତେବେଳେ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		ଯଦି (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), ଖାଲି);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	ଯଦି (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
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

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	/* none */
}
