/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <ctype.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"
#شامل "sshbuf.h"

تهی mldsa_tests(تهی);
تهی mlkem_tests(تهی);
تهی ed25519_tests(تهی);
تهی mldsa_eddsa_tests(تهی);

ساختار sshbuf *load_text_file(ثابت نویسه *name);
نویسه *get_json_string(ساختار sshbuf *content, ثابت نویسه *کلید, صحیح consume);

ایستا ساختار sshbuf *
load_file(ثابت نویسه *name)
{
	ساختار sshbuf *ret = پوچ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, پوچ);
	بازگشت ret;
}

ساختار sshbuf *
load_text_file(ثابت نویسه *name)
{
	ساختار sshbuf *ret = load_file(name);
	ثابت u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	برای (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		اگر (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		وگرنه
			بشکن;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	بازگشت ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
نویسه *
get_json_string(ساختار sshbuf *content, ثابت نویسه *کلید, صحیح consume)
{
	ساختار sshbuf *tmp;
	نویسه *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, پوچ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", کلید), 0);
	اگر (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	آزاد(k);

	/* Skip colon, spaces, commas */
	وقتی (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		اگر (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		وگرنه
			بشکن;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), پوچ);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	اگر (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	بازگشت ret;
}

تهی
tests(تهی)
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

تهی
benchmarks(تهی)
{
	/* none */
}
