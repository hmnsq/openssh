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

संरचना sshbuf *load_text_file(ध्रुव वर्ण *name);
वर्ण *get_json_string(संरचना sshbuf *content, ध्रुव वर्ण *कुंजी, पूर्णाङ्क consume);

स्थिर संरचना sshbuf *
load_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	प्रत्यागम ret;
}

संरचना sshbuf *
load_text_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = load_file(name);
	ध्रुव u_char *p;
	माप_प्रकार len;

	/* Trim whitespace at EOL */
	प्रति (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		यदि (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
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
get_json_string(संरचना sshbuf *content, ध्रुव वर्ण *कुंजी, पूर्णाङ्क consume)
{
	संरचना sshbuf *tmp;
	वर्ण *k, *ret;
	माप_प्रकार off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, रिक्त);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", कुंजी), 0);
	यदि (sshbuf_find(tmp, 0, k, म_माप(k), &off) != 0) {
		ख_लिखो(मानक_त्रुटि, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + म_माप(k)), 0);
	मुक्त(k);

	/* Skip colon, spaces, commas */
	यावत् (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		यदि (है_खाली(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		अन्यथा
			भङ्ग;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = दो_स्मृति(end_off + 1), रिक्त);
	स_नकल(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	यदि (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	प्रत्यागम ret;
}

शून्य
tests(शून्य)
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

शून्य
benchmarks(शून्य)
{
	/* none */
}
