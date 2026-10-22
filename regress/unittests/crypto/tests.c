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

خالی mldsa_tests(خالی);
خالی mlkem_tests(خالی);
خالی ed25519_tests(خالی);
خالی mldsa_eddsa_tests(خالی);

ساخت sshbuf *بھرو_متن_file(ثابت حرف *name);
حرف *get_json_string(ساخت sshbuf *content, ثابت حرف *کلید, صحیح consume);

ساکن ساخت sshbuf *
بھرو_file(ثابت حرف *name)
{
	ساخت sshbuf *ret = تہی;

	ASSERT_INT_EQ(sshbuf_بھرو_file(test_ڈیٹا_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, تہی);
	واپس ret;
}

ساخت sshbuf *
بھرو_متن_file(ثابت حرف *name)
{
	ساخت sshbuf *ret = بھرو_file(name);
	ثابت u_char *p;
	سائز_t len;

	/* Trim whitespace at EOL */
	برائے (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		اگر (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_انتہا(ret, 1), 0);
		ورنہ
			توڑو;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	واپس ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
حرف *
get_json_string(ساخت sshbuf *content, ثابت حرف *کلید, صحیح consume)
{
	ساخت sshbuf *tmp;
	حرف *k, *ret;
	سائز_t off, انتہا_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, تہی);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", کلید), 0);
	اگر (sshbuf_ڈھونڈو(tmp, 0, k, لڑی_لمبائی(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + لڑی_لمبائی(k)), 0);
	آزاد(k);

	/* Skip colon, spaces, commas */
	جب (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		اگر (خلا_ہے(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		ورنہ
			توڑو;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(tmp, 0, "\"", 1, &انتہا_off), 0);
	ASSERT_PTR_NE(ret = حافظہ_دو(انتہا_off + 1), تہی);
	حافظہ_نقل(ret, sshbuf_ptr(tmp), انتہا_off);
	ret[انتہا_off] = '\0';
	اگر (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, انتہا_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_بچہ(content, tmp), 0);
	}
	sshbuf_free(tmp);
	واپس ret;
}

خالی
tests(خالی)
{
#اگر_تعریف_شدہ USE_MLDSA
	mldsa_tests();
#اگر_ختم
#اگر_تعریف_شدہ USE_MLKEM768X25519
	mlkem_tests();
#اگر_ختم
	ed25519_tests();
#اگر_تعریف_شدہ USE_MLDSA
	mldsa_eddsa_tests();
#اگر_ختم
}

خالی
benchmarks(خالی)
{
	/* none */
}
