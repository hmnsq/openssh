/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <ctype.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"
#समावेश "sshbuf.h"

व्योम mldsa_tests(व्योम);
व्योम mlkem_tests(व्योम);
व्योम ed25519_tests(व्योम);
व्योम mldsa_eddsa_tests(व्योम);

काष्ठा sshbuf *load_text_file(स्थिर अक्षर *name);
अक्षर *get_json_string(काष्ठा sshbuf *content, स्थिर अक्षर *कुंजी, पूर्णांक consume);

अटल काष्ठा sshbuf *
load_file(स्थिर अक्षर *name)
{
	काष्ठा sshbuf *ret = शून्य;

	ASSERT_INT_EQ(sshbuf_load_file(test_तथ्य_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, शून्य);
	वापस ret;
}

काष्ठा sshbuf *
load_text_file(स्थिर अक्षर *name)
{
	काष्ठा sshbuf *ret = load_file(name);
	स्थिर u_char *p;
	माप_प्रकार len;

	/* Trim whitespace at EOL */
	क्रम (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		अगर (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		अन्यथा
			अवरोध;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	वापस ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
अक्षर *
get_json_string(काष्ठा sshbuf *content, स्थिर अक्षर *कुंजी, पूर्णांक consume)
{
	काष्ठा sshbuf *tmp;
	अक्षर *k, *ret;
	माप_प्रकार off, end_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, शून्य);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", कुंजी), 0);
	अगर (sshbuf_find(tmp, 0, k, म_माप(k), &off) != 0) {
		ख_लिखो(मानक_त्रुटि, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + म_माप(k)), 0);
	मुक्त(k);

	/* Skip colon, spaces, commas */
	जबतक (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		अगर (है_खाली(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		अन्यथा
			अवरोध;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_find(tmp, 0, "\"", 1, &end_off), 0);
	ASSERT_PTR_NE(ret = दो_स्मृति(end_off + 1), शून्य);
	स_नकल(ret, sshbuf_ptr(tmp), end_off);
	ret[end_off] = '\0';
	अगर (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, end_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_child(content, tmp), 0);
	}
	sshbuf_free(tmp);
	वापस ret;
}

व्योम
tests(व्योम)
{
#अगर_घोषित USE_MLDSA
	mldsa_tests();
#पूर्ण_अगर
#अगर_घोषित USE_MLKEM768X25519
	mlkem_tests();
#पूर्ण_अगर
	ed25519_tests();
#अगर_घोषित USE_MLDSA
	mldsa_eddsa_tests();
#पूर्ण_अगर
}

व्योम
benchmarks(व्योम)
{
	/* none */
}
