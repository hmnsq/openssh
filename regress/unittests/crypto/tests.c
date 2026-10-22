/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಶೂನ್ಯ mldsa_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ mlkem_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ ed25519_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ mldsa_eddsa_tests(ಶೂನ್ಯ);

ರಚನೆ sshbuf *ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಅಕ್ಷರ *get_json_string(ರಚನೆ sshbuf *content, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ consume);

ಸ್ಥಿರ ರಚನೆ sshbuf *
ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *ret = ಖಾಲಿ;

	ASSERT_INT_EQ(sshbuf_ತುಂಬು_file(test_ದತ್ತಾಂಶ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ sshbuf *
ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *ret = ತುಂಬು_file(name);
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಗಾತ್ರ_t len;

	/* Trim whitespace at EOL */
	ಗಾಗಿ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ಆದರೆ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_ಕೊನೆ(ret, 1), 0);
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ಹಿಂತಿರುಗಿ ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
ಅಕ್ಷರ *
get_json_string(ರಚನೆ sshbuf *content, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ consume)
{
	ರಚನೆ sshbuf *tmp;
	ಅಕ್ಷರ *k, *ret;
	ಗಾತ್ರ_t off, ಕೊನೆ_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ಖಾಲಿ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", ಕೀಲಿ), 0);
	ಆದರೆ (sshbuf_ಕಂಡುಹಿಡಿ(tmp, 0, k, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(k)), 0);
	ಬಿಡುಗಡೆ(k);

	/* Skip colon, spaces, commas */
	ಆಗ (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		ಆದರೆ (ಖಾಲಿಯೇ(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(tmp, 0, "\"", 1, &ಕೊನೆ_off), 0);
	ASSERT_PTR_NE(ret = ಸ್ಮರಣೆ_ಕೊಡು(ಕೊನೆ_off + 1), ಖಾಲಿ);
	ಸ್ಮರಣೆ_ನಕಲು(ret, sshbuf_ptr(tmp), ಕೊನೆ_off);
	ret[ಕೊನೆ_off] = '\0';
	ಆದರೆ (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, ಕೊನೆ_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_ಮಗು(content, tmp), 0);
	}
	sshbuf_free(tmp);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA
	mldsa_tests();
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLKEM768X25519
	mlkem_tests();
#ಆದರೆ_ಅಂತ್ಯ
	ed25519_tests();
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA
	mldsa_eddsa_tests();
#ಆದರೆ_ಅಂತ್ಯ
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	/* none */
}
