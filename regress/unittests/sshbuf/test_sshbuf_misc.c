/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "sshbuf.h"
#समावेश "ssherr.h"

व्योम sshbuf_misc_tests(व्योम);

अटल व्योम
test_sshbuf_dump(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर tmp[512];
	खाता *out;
	माप_प्रकार sz;

	TEST_START("sshbuf_dump");
	out = क्षणिक_ख();
	ASSERT_PTR_NE(out, शून्य);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, out);
	ख_साफ(out);
	शुरुआत(out);
	sz = ख_पढ़ो(tmp, 1, माप(tmp), out);
	ASSERT_INT_EQ(ख_त्रुटि(out), 0);
	ASSERT_INT_NE(ख_पूर्ण(out), 0);
	ASSERT_आकार_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(म_माला(tmp, "12 34 56 78"), शून्य);
	ख_बंद(out);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_dtob16(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर *p;

	TEST_START("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_STRING_EQ(p, "12345678");
	मुक्त(p);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_dtob64_string(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर *p;

	TEST_START("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_STRING_EQ(p, "EQ==");
	मुक्त(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_STRING_EQ(p, "ESI=");
	मुक्त(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_STRING_EQ(p, "ESIz");
	मुक्त(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, शून्य), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_आकार_T_EQ(म_माप(p), ((8191 + 2) / 3) * 4);
	मुक्त(p);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_b64tod(व्योम)
{
	काष्ठा sshbuf *p1;

	TEST_START("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_dup_string(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर *p;

	TEST_START("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_आकार_T_EQ(म_माप(p), 0);
	मुक्त(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", म_माप("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_आकार_T_EQ(म_माप(p), म_माप("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	मुक्त(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, शून्य);
	ASSERT_आकार_T_EQ(म_माप(p), म_माप("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	मुक्त(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", म_माप("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, शून्य);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_cmp(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर संदेश[] = "imploring ping silence ping over";

	TEST_START("sshbuf_cmp");
	p1 = sshbuf_from(संदेश, माप(संदेश) - 1);
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "i", 1), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "j", 1), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "imploring", 9), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "implored", 9), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ping", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ring", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "over", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "rove", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "overt", 5),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 32, "ping", 4),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 1000, "silence", 7),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, संदेश, माप(संदेश) - 1), 0);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_find(व्योम)
{
	काष्ठा sshbuf *p1;
	अक्षर संदेश[] = "imploring ping silence ping over";
	माप_प्रकार sz;

	TEST_START("sshbuf_find");
	p1 = sshbuf_from(संदेश, माप(संदेश) - 1);
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "i", 1, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 3, "ping", 4, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_find(p1, 11, "ping", 4, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_find(p1, 20, "over", 4, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "over", 4, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "overt", 5, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 32, "ping", 4, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, संदेश + 1, माप(संदेश) - 2, &sz), 0);
	ASSERT_आकार_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_equals(व्योम)
{
	काष्ठा sshbuf *b1, *b2;

	TEST_START("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_PTR_NE(b2, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_PTR_NE(b2, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_PTR_NE(b2, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_PTR_NE(b2, शून्य);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_PTR_NE(b2, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_DONE();
}

अटल व्योम
test_sshbuf_dtourlb64(व्योम)
{
	काष्ठा sshbuf *b, *b64;
	अक्षर *s;
	/* From RFC4648 */
	स्थिर u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	स्थिर u_char test_vec2[] = {0xff, 0xff, 0xff};
	स्थिर u_char test_vec3[] = {0xfb};

	TEST_START("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_PTR_NE(b64, शून्य);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_PTR_NE(b64, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, शून्य);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	मुक्त(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_PTR_NE(b64, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, माप(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, शून्य);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	मुक्त(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_PTR_NE(b64, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, माप(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, शून्य);
	ASSERT_STRING_EQ(s, "____");
	मुक्त(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, शून्य);
	ASSERT_PTR_NE(b64, शून्य);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, माप(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, शून्य);
	ASSERT_STRING_EQ(s, "-w");
	मुक्त(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();
}

व्योम
sshbuf_misc_tests(व्योम)
{
	test_sshbuf_dump();
	test_sshbuf_dtob16();
	test_sshbuf_dtob64_string();
	test_sshbuf_b64tod();
	test_sshbuf_dup_string();
	test_sshbuf_cmp();
	test_sshbuf_find();
	test_sshbuf_equals();
	test_sshbuf_dtourlb64();
}

