/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <ctype.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"
#ضمن "sshbuf.h"

فراغ mldsa_tests(فراغ);
فراغ mlkem_tests(فراغ);
فراغ ed25519_tests(فراغ);
فراغ mldsa_eddsa_tests(فراغ);

بنية sshbuf *load_text_file(ثابت حرف *name);
حرف *get_json_string(بنية sshbuf *content, ثابت حرف *key, صحيح consume);

ساكن بنية sshbuf *
load_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

بنية sshbuf *
load_text_file(ثابت حرف *name)
{
	بنية sshbuf *ret = load_file(name);
	ثابت u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	لكل (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		𐡄𐡍 (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		وإلا
			اكسر;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	أرجع ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
حرف *
get_json_string(بنية sshbuf *content, ثابت حرف *key, صحيح consume)
{
	بنية sshbuf *tmp;
	حرف *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, عدم);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", key), 0);
	𐡄𐡍 (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	حرر(k);

	/* Skip colon, spaces, commas */
	طالما (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		𐡄𐡍 (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		وإلا
			اكسر;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), عدم);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	𐡄𐡍 (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	أرجع ret;
}

فراغ
tests(فراغ)
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

فراغ
benchmarks(فراغ)
{
	/* none */
}
