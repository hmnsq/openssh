/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਖਾਲੀ mldsa_tests(ਖਾਲੀ);
ਖਾਲੀ mlkem_tests(ਖਾਲੀ);
ਖਾਲੀ ed25519_tests(ਖਾਲੀ);
ਖਾਲੀ mldsa_eddsa_tests(ਖਾਲੀ);

ਬਣਤਰ sshbuf *ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name);
ਅੱਖਰ *get_json_string(ਬਣਤਰ sshbuf *content, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ, ਪੂਰਨ consume);

ਸਥਿਰ ਬਣਤਰ sshbuf *
ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *ret = ਨਿਰਾ;

	ASSERT_INT_EQ(sshbuf_ਲੱਦੋ_file(test_ਅੰਕੜੇ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ਵਾਪਸ ret;
}

ਬਣਤਰ sshbuf *
ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *ret = ਲੱਦੋ_file(name);
	ਅਚਲ u_char *p;
	ਮਾਪ_t len;

	/* Trim whitespace at EOL */
	ਲਈ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ਜੇ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(ret, 1), 0);
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ਵਾਪਸ ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
ਅੱਖਰ *
get_json_string(ਬਣਤਰ sshbuf *content, ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ, ਪੂਰਨ consume)
{
	ਬਣਤਰ sshbuf *tmp;
	ਅੱਖਰ *k, *ret;
	ਮਾਪ_t off, ਸਿਰਾ_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ਨਿਰਾ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", ਕੁੰਜੀ), 0);
	ਜੇ (sshbuf_ਲੱਭੋ(tmp, 0, k, ਲੜੀ_ਲੰਬਾਈ(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + ਲੜੀ_ਲੰਬਾਈ(k)), 0);
	ਮੁਕਤ(k);

	/* Skip colon, spaces, commas */
	ਜਦੋਂ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		ਜੇ (ਖਾਲੀ_ਥਾਂ_ਹੈ(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(tmp, 0, "\"", 1, &ਸਿਰਾ_off), 0);
	ASSERT_PTR_NE(ret = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਸਿਰਾ_off + 1), ਨਿਰਾ);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ret, sshbuf_ptr(tmp), ਸਿਰਾ_off);
	ret[ਸਿਰਾ_off] = '\0';
	ਜੇ (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, ਸਿਰਾ_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_ਬੱਚਾ(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
tests(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA
	mldsa_tests();
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLKEM768X25519
	mlkem_tests();
#ਜੇ_ਅੰਤ
	ed25519_tests();
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA
	mldsa_eddsa_tests();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	/* none */
}
