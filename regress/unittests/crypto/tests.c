/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"
#অন্তর্ভাব "sshbuf.h"

শূন্য mldsa_tests(শূন্য);
শূন্য mlkem_tests(শূন্য);
শূন্য ed25519_tests(শূন্য);
শূন্য mldsa_eddsa_tests(শূন্য);

কাঠামো sshbuf *load_text_file(ধ্রুবক অক্ষর *name);
অক্ষর *get_json_string(কাঠামো sshbuf *content, ধ্রুবক অক্ষর *চাবি, পূর্ণসংখ্যা consume);

স্থির কাঠামো sshbuf *
load_file(ধ্রুবক অক্ষর *name)
{
	কাঠামো sshbuf *ret = ফাঁকা;

	ASSERT_INT_EQ(sshbuf_load_file(test_তথ্য_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ফাঁকা);
	ফেরত ret;
}

কাঠামো sshbuf *
load_text_file(ধ্রুবক অক্ষর *name)
{
	কাঠামো sshbuf *ret = load_file(name);
	ধ্রুবক u_char *p;
	আকার_t len;

	/* Trim whitespace at EOL */
	জন্য (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		যদি (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		অন্যথা
			বিরতি;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ফেরত ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
অক্ষর *
get_json_string(কাঠামো sshbuf *content, ধ্রুবক অক্ষর *চাবি, পূর্ণসংখ্যা consume)
{
	কাঠামো sshbuf *tmp;
	অক্ষর *k, *ret;
	আকার_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ফাঁকা);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", চাবি), 0);
	যদি (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	মুক্ত(k);

	/* Skip colon, spaces, commas */
	যখন (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		যদি (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		অন্যথা
			বিরতি;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), ফাঁকা);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	যদি (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ফেরত ret;
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
