/* 	$OpenBSD: tests.c,v 1.2 2026/06/16 08:15:35 dtucker Exp $ */
/*
 * Regress test for crypto ergonomic API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"
#అన్తర్భావ "sshbuf.h"

శూన్య mldsa_tests(శూన్య);
శూన్య mlkem_tests(శూన్య);
శూన్య ed25519_tests(శూన్య);
శూన్య mldsa_eddsa_tests(శూన్య);

నిర్మాణం sshbuf *ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name);
అక్షరం *get_json_string(నిర్మాణం sshbuf *content, స్థిరరాశి అక్షరం *కీలకం, పూర్ణాంకం consume);

స్థిర నిర్మాణం sshbuf *
ఎక్కించు_file(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *ret = ఖాళీ;

	ASSERT_INT_EQ(sshbuf_ఎక్కించు_file(test_దత్తాంశం_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ఖాళీ);
	తిరిగి ret;
}

నిర్మాణం sshbuf *
ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *ret = ఎక్కించు_file(name);
	స్థిరరాశి u_char *p;
	కొలత_t len;

	/* Trim whitespace at EOL */
	కొరకు (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ఒకవేళ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_చివర(ret, 1), 0);
		లేకపోతే
			ఆపు;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	తిరిగి ret;
}


/*
 * Simple JSON-ish parser for test vectors.
 * Extracts the value for a given key.
 * Errors cause ASSERT_* failures.
 */
అక్షరం *
get_json_string(నిర్మాణం sshbuf *content, స్థిరరాశి అక్షరం *కీలకం, పూర్ణాంకం consume)
{
	నిర్మాణం sshbuf *tmp;
	అక్షరం *k, *ret;
	కొలత_t off, చివర_off;
	u_char c;

	tmp = sshbuf_fromb(content);
	ASSERT_PTR_NE(tmp, ఖాళీ);
	ASSERT_INT_GT(asprintf(&k, "\"%s\"", కీలకం), 0);
	ఒకవేళ (sshbuf_కనుగొను(tmp, 0, k, అక్షరశ్రేణి_పొడవు(k), &off) != 0) {
		fprintf(stderr, "Key %s not found in JSON\n", k);
		ASSERT_INT_EQ(1, 0);
	}
	ASSERT_INT_EQ(sshbuf_consume(tmp, off + అక్షరశ్రేణి_పొడవు(k)), 0);
	విడుదల(k);

	/* Skip colon, spaces, commas */
	అయితే (sshbuf_len(tmp) > 0) {
		c = *sshbuf_ptr(tmp);
		ఒకవేళ (ఖాళీనా(c) || c == ':' || c == ',')
			ASSERT_INT_EQ(sshbuf_consume(tmp, 1), 0);
		లేకపోతే
			ఆపు;
	}
	/* Expect opening quote */
	ASSERT_INT_EQ(sshbuf_get_u8(tmp, &c), 0);
	ASSERT_CHAR_EQ(c, '"');
	/* Find closing quote */
	ASSERT_INT_EQ(sshbuf_కనుగొను(tmp, 0, "\"", 1, &చివర_off), 0);
	ASSERT_PTR_NE(ret = జ్ఞాపకం_ఇవ్వు(చివర_off + 1), ఖాళీ);
	జ్ఞాపకం_నకలు(ret, sshbuf_ptr(tmp), చివర_off);
	ret[చివర_off] = '\0';
	ఒకవేళ (consume) {
		ASSERT_INT_EQ(sshbuf_consume(tmp, చివర_off), 0);
		ASSERT_INT_EQ(sshbuf_consume_upto_బిడ్డ(content, tmp), 0);
	}
	sshbuf_free(tmp);
	తిరిగి ret;
}

శూన్య
tests(శూన్య)
{
#నిర్వచితమైతే USE_MLDSA
	mldsa_tests();
#అయితే_ముగింపు
#నిర్వచితమైతే USE_MLKEM768X25519
	mlkem_tests();
#అయితే_ముగింపు
	ed25519_tests();
#నిర్వచితమైతే USE_MLDSA
	mldsa_eddsa_tests();
#అయితే_ముగింపు
}

శూన్య
benchmarks(శూన్య)
{
	/* none */
}
