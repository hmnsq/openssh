/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"
#അന്തര്ഭാവ "sshbuf.h"

ശൂന്യം mldsa_tests(ശൂന്യം);
ശൂന്യം mlkem_tests(ശൂന്യം);
ശൂന്യം ed25519_tests(ശൂന്യം);
ശൂന്യം mldsa_eddsa_tests(ശൂന്യം);

ഘടന sshbuf *load_text_file(സ്ഥിരം അക്ഷരം *name);
അക്ഷരം *get_json_string(ഘടന sshbuf *content, സ്ഥിരം അക്ഷരം *താക്കോൽ, പൂർണ്ണസംഖ്യ consume);

സ്ഥിതം ഘടന sshbuf *
load_file(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *ret = ശൂന്യ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ശൂന്യ);
	തിരികെ ret;
}

ഘടന sshbuf *
load_text_file(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *ret = load_file(name);
	സ്ഥിരം u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	വേണ്ടി (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		എങ്കിൽ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	തിരികെ ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
അക്ഷരം *
get_json_string(ഘടന sshbuf *content, സ്ഥിരം അക്ഷരം *താക്കോൽ, പൂർണ്ണസംഖ്യ consume)
{
	ഘടന sshbuf *tmp;
	അക്ഷരം *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ശൂന്യ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", താക്കോൽ), 0);
	എങ്കിൽ (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	സ്വതന്ത്രം(k);

	/* Skip colon, spaces, commas */
	ആകുമ്പോൾ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		എങ്കിൽ (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), ശൂന്യ);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	എങ്കിൽ (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	തിരികെ ret;
}

ശൂന്യം
tests(ശൂന്യം)
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

ശൂന്യം
benchmarks(ശൂന്യം)
{
	/* none */
}
