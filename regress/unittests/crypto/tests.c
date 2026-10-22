/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"
#अन्तर्भाव "sshbuf.h"

शून्य mldsa_tests(शून्य);
शून्य mlkem_tests(शून्य);
शून्य ed25519_tests(शून्य);
शून्य mldsa_eddsa_tests(शून्य);

संरचना sshbuf *आरोपय_text_file(ध्रुव वर्ण *name);
वर्ण *get_json_string(संरचना sshbuf *content, ध्रुव वर्ण *कुञ्चिका, पूर्णाङ्क consume);

स्थिर संरचना sshbuf *
आरोपय_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_आरोपय_file(test_दत्त_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	प्रत्यागम ret;
}

संरचना sshbuf *
आरोपय_text_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = आरोपय_file(name);
	ध्रुव u_char *p;
	आकार_t len;

	/* Trim whitespace at EOL */
	प्रति (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		यदि (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_अन्तः(ret, 1), 0);
		अन्यथा
			भङ्ग;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	प्रत्यागम ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
वर्ण *
get_json_string(संरचना sshbuf *content, ध्रुव वर्ण *कुञ्चिका, पूर्णाङ्क consume)
{
	संरचना sshbuf *tmp;
	वर्ण *k, *ret;
	आकार_t off, अन्तः_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, रिक्त);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", कुञ्चिका), 0);
	यदि (sshbuf_find(tmp, 0, k, वाक्यदैर्घ्यम्(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + वाक्यदैर्घ्यम्(k)), 0);
	मुक्त(k);

	/* Skip colon, spaces, commas */
	यावत् (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		यदि (रिक्तम्_वा(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		अन्यथा
			भङ्ग;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &अन्तः_off), 0);
	ASSERT_PTR_NE(ret = स्मृतिं_देहि(अन्तः_off + 1), रिक्त);
	स्मृतिं_प्रतिलिख(ret, sshbuf_ptr(tmp), अन्तः_off);
	ret[अन्तः_off] = '\0';
	यदि (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, अन्तः_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	प्रत्यागम ret;
}

शून्य
tests(शून्य)
{
#यदि_परिभाषितम् USE_MLDSA
	mldsa_tests();
#यदि_अन्तः
#यदि_परिभाषितम् USE_MLKEM768X25519
	mlkem_tests();
#यदि_अन्तः
	ed25519_tests();
#यदि_परिभाषितम् USE_MLDSA
	mldsa_eddsa_tests();
#यदि_अन्तः
}

शून्य
benchmarks(शून्य)
{
	/* none */
}
