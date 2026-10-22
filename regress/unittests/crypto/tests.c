/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"
#include "sshbuf.h"

void mldsa_tests(void);
void mlkem_tests(void);
void ed25519_tests(void);
void mldsa_eddsa_tests(void);

struct sshbuf *load_text_file(const char *name);
char *get_json_string(struct sshbuf *content, const char *key, 정수 consume);

static struct sshbuf *
load_file(const char *name)
{
	struct sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	반환 ret;
}

struct sshbuf *
load_text_file(const char *name)
{
	struct sshbuf *ret = load_file(name);
	const u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	위해 (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		만약 (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		아니면
			break;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	반환 ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
char *
get_json_string(struct sshbuf *content, const char *key, 정수 consume)
{
	struct sshbuf *tmp;
	char *k, *ret;
	size_t off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, NULL);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", key), 0);
	만약 (sshbuf_find(tmp, 0, k, strlen(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + strlen(k)), 0);
	free(k);

	/* Skip colon, spaces, commas */
	동안 (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		만약 (isspace(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		아니면
			break;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = malloc(end_off + 1), NULL);
	memcpy(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	만약 (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	반환 ret;
}

void
tests(void)
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

void
benchmarks(void)
{
	/* none */
}
