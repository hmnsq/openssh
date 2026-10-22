/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"

శూన్య sshbuf_misc_tests(శూన్య);

స్థిర శూన్య
test_sshbuf_dump(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం tmp[512];
	FILE *బహిర్గతం;
	కొలత_t sz;

	TEST_ప్రారంభం("sshbuf_dump");
	బహిర్గతం = tmpfile();
	ASSERT_PTR_NE(బహిర్గతం, ఖాళీ);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, బహిర్గతం);
	fflush(బహిర్గతం);
	rewind(బహిర్గతం);
	sz = fread(tmp, 1, పరిమాణం(tmp), బహిర్గతం);
	ASSERT_INT_EQ(ferror(బహిర్గతం), 0);
	ASSERT_INT_NE(feof(బహిర్గతం), 0);
	ASSERT_కొలత_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(అక్షరశ్రేణి_శోధన(tmp, "12 34 56 78"), ఖాళీ);
	fclose(బహిర్గతం);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_dtob16(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం *p;

	TEST_ప్రారంభం("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_STRING_EQ(p, "12345678");
	విడుదల(p);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_dtob64_string(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం *p;

	TEST_ప్రారంభం("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_STRING_EQ(p, "EQ==");
	విడుదల(p);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_STRING_EQ(p, "ESI=");
	విడుదల(p);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_STRING_EQ(p, "ESIz");
	విడుదల(p);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, ఖాళీ), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_కొలత_T_EQ(అక్షరశ్రేణి_పొడవు(p), ((8191 + 2) / 3) * 4);
	విడుదల(p);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_b64tod(శూన్య)
{
	నిర్మాణం sshbuf *p1;

	TEST_ప్రారంభం("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_dup_string(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం *p;

	TEST_ప్రారంభం("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_కొలత_T_EQ(అక్షరశ్రేణి_పొడవు(p), 0);
	విడుదల(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", అక్షరశ్రేణి_పొడవు("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_కొలత_T_EQ(అక్షరశ్రేణి_పొడవు(p), అక్షరశ్రేణి_పొడవు("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	విడుదల(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ఖాళీ);
	ASSERT_కొలత_T_EQ(అక్షరశ్రేణి_పొడవు(p), అక్షరశ్రేణి_పొడవు("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	విడుదల(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", అక్షరశ్రేణి_పొడవు("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, ఖాళీ);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_cmp(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం సందేశం[] = "imploring ping silence ping over";

	TEST_ప్రారంభం("sshbuf_cmp");
	p1 = sshbuf_from(సందేశం, పరిమాణం(సందేశం) - 1);
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "i", 1), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "j", 1), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "imploring", 9), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "implored", 9), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ping", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ring", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "over", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "rove", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "overt", 5),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 32, "ping", 4),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 1000, "silence", 7),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, సందేశం, పరిమాణం(సందేశం) - 1), 0);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_కనుగొను(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	అక్షరం సందేశం[] = "imploring ping silence ping over";
	కొలత_t sz;

	TEST_ప్రారంభం("sshbuf_find");
	p1 = sshbuf_from(సందేశం, పరిమాణం(సందేశం) - 1);
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 0, "i", 1, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 3, "ping", 4, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 11, "ping", 4, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 20, "over", 4, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 28, "over", 4, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 28, "overt", 5, &sz),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 32, "ping", 4, &sz),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_కనుగొను(p1, 0, సందేశం + 1, పరిమాణం(సందేశం) - 2, &sz), 0);
	ASSERT_కొలత_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_equals(శూన్య)
{
	నిర్మాణం sshbuf *b1, *b2;

	TEST_ప్రారంభం("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_PTR_NE(b2, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_PTR_NE(b2, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_PTR_NE(b2, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_సందేశం_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_PTR_NE(b2, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_PTR_NE(b2, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_సందేశం_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_పూర్తి();
}

స్థిర శూన్య
test_sshbuf_dtourlb64(శూన్య)
{
	నిర్మాణం sshbuf *b, *b64;
	అక్షరం *s;
	/* From RFC4648 */
	స్థిరరాశి u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	స్థిరరాశి u_char test_vec2[] = {0xff, 0xff, 0xff};
	స్థిరరాశి u_char test_vec3[] = {0xfb};

	TEST_ప్రారంభం("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_PTR_NE(b64, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_PTR_NE(b64, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	విడుదల(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_PTR_NE(b64, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, పరిమాణం(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	విడుదల(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_PTR_NE(b64, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, పరిమాణం(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "____");
	విడుదల(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	ASSERT_PTR_NE(b64, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, పరిమాణం(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ఖాళీ);
	ASSERT_STRING_EQ(s, "-w");
	విడుదల(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_పూర్తి();
}

శూన్య
sshbuf_misc_tests(శూన్య)
{
	test_sshbuf_dump();
	test_sshbuf_dtob16();
	test_sshbuf_dtob64_string();
	test_sshbuf_b64tod();
	test_sshbuf_dup_string();
	test_sshbuf_cmp();
	test_sshbuf_కనుగొను();
	test_sshbuf_equals();
	test_sshbuf_dtourlb64();
}

