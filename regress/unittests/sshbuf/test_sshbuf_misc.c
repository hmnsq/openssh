/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "sshbuf.h"
#ضمن "ssherr.h"

فراغ sshbuf_misc_tests(فراغ);

ساكن فراغ
test_sshbuf_dump(فراغ)
{
	بنية sshbuf *p1;
	حرف tmp[512];
	FILE *out;
	size_t sz;

	TEST_START("sshbuf_dump");
	out = tmpfile();
	ASSERT_PTR_NE(out, عدم);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, out);
	fflush(out);
	rewind(out);
	sz = fread(tmp, 1, حجم(tmp), out);
	ASSERT_INT_EQ(ferror(out), 0);
	ASSERT_INT_NE(feof(out), 0);
	ASSERT_SIZE_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(strstr(tmp, "12 34 56 78"), عدم);
	fclose(out);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_dtob16(فراغ)
{
	بنية sshbuf *p1;
	حرف *p;

	TEST_START("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_STRING_EQ(p, "12345678");
	حرر(p);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_dtob64_string(فراغ)
{
	بنية sshbuf *p1;
	حرف *p;

	TEST_START("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_STRING_EQ(p, "EQ==");
	حرر(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_STRING_EQ(p, "ESI=");
	حرر(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_STRING_EQ(p, "ESIz");
	حرر(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, عدم), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_SIZE_T_EQ(strlen(p), ((8191 + 2) / 3) * 4);
	حرر(p);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_b64tod(فراغ)
{
	بنية sshbuf *p1;

	TEST_START("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_dup_string(فراغ)
{
	بنية sshbuf *p1;
	حرف *p;

	TEST_START("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_SIZE_T_EQ(strlen(p), 0);
	حرر(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", strlen("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_SIZE_T_EQ(strlen(p), strlen("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	حرر(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, عدم);
	ASSERT_SIZE_T_EQ(strlen(p), strlen("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	حرر(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", strlen("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, عدم);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_cmp(فراغ)
{
	بنية sshbuf *p1;
	حرف پەیام[] = "imploring ping silence ping over";

	TEST_START("sshbuf_cmp");
	p1 = sshbuf_from(پەیام, حجم(پەیام) - 1);
	ASSERT_PTR_NE(p1, عدم);
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
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, پەیام, حجم(پەیام) - 1), 0);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_find(فراغ)
{
	بنية sshbuf *p1;
	حرف پەیام[] = "imploring ping silence ping over";
	size_t sz;

	TEST_START("sshbuf_find");
	p1 = sshbuf_from(پەیام, حجم(پەیام) - 1);
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "i", 1, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 3, "ping", 4, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_find(p1, 11, "ping", 4, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_find(p1, 20, "over", 4, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "over", 4, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_find(p1, 28, "overt", 5, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 32, "ping", 4, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_find(p1, 0, پەیام + 1, حجم(پەیام) - 2, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_equals(فراغ)
{
	بنية sshbuf *b1, *b2;

	TEST_START("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_PTR_NE(b2, عدم);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_PTR_NE(b2, عدم);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_PTR_NE(b2, عدم);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_PTR_NE(b2, عدم);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_PTR_NE(b2, عدم);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, عدم);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_DONE();
}

ساكن فراغ
test_sshbuf_dtourlb64(فراغ)
{
	بنية sshbuf *b, *b64;
	حرف *s;
	/* From RFC4648 */
	ثابت u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	ثابت u_char test_vec2[] = {0xff, 0xff, 0xff};
	ثابت u_char test_vec3[] = {0xfb};

	TEST_START("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_PTR_NE(b64, عدم);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_PTR_NE(b64, عدم);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	حرر(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_PTR_NE(b64, عدم);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, حجم(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	حرر(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_PTR_NE(b64, عدم);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, حجم(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "____");
	حرر(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, عدم);
	ASSERT_PTR_NE(b64, عدم);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, حجم(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, عدم);
	ASSERT_STRING_EQ(s, "-w");
	حرر(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();
}

فراغ
sshbuf_misc_tests(فراغ)
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

