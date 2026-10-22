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

بنية sshbuf *لدو_متن_file(ثابت حرف *name);
حرف *get_json_string(بنية sshbuf *content, ثابت حرف *کلید, صحيح consume);

ساكن بنية sshbuf *
لدو_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_لدو_file(test_انکڑے_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

بنية sshbuf *
لدو_متن_file(ثابت حرف *name)
{
	بنية sshbuf *ret = لدو_file(name);
	ثابت u_char *p;
	ناپ_t len;

	/* Trim whitespace at EOL */
	لكل (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		إذا (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_سرا(ret, 1), 0);
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
get_json_string(بنية sshbuf *content, ثابت حرف *کلید, صحيح consume)
{
	بنية sshbuf *tmp;
	حرف *k, *ret;
	ناپ_t off, سرا_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, عدم);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", کلید), 0);
	إذا (sshbuf_لبھو(tmp, 0, k, لڑی_لمبائی(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + لڑی_لمبائی(k)), 0);
	حرر(k);

	/* Skip colon, spaces, commas */
	طالما (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		إذا (خلا_اے(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		وإلا
			اكسر;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_لبھو(tmp, 0, "\"", 1, &سرا_off), 0);
	ASSERT_PTR_NE(ret = حافظہ_دیو(سرا_off + 1), عدم);
	حافظہ_نقل(ret, sshbuf_ptr(tmp), سرا_off);
	ret[سرا_off] = '\0';
	إذا (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, سرا_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_بچہ(content, tmp), 0);
	}
	sshbuf_free(tmp);
	أرجع ret;
}

فراغ
tests(فراغ)
{
#جے_تعریف_شدہ USE_MLDSA
	mldsa_tests();
#جے_انت
#جے_تعریف_شدہ USE_MLKEM768X25519
	mlkem_tests();
#جے_انت
	ed25519_tests();
#جے_تعریف_شدہ USE_MLDSA
	mldsa_eddsa_tests();
#جے_انت
}

فراغ
benchmarks(فراغ)
{
	/* none */
}
