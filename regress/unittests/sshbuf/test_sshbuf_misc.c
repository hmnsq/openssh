/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಶೂನ್ಯ sshbuf_misc_tests(ಶೂನ್ಯ);

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dump(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ tmp[512];
	FILE *out;
	size_t sz;

	TEST_START("sshbuf_dump");
	out = tmpfile();
	ASSERT_PTR_NE(out, ರಿಕ್ತ);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, out);
	fflush(out);
	rewind(out);
	sz = fread(tmp, 1, ಪರಿಮಾಣ(tmp), out);
	ASSERT_INT_EQ(ferror(out), 0);
	ASSERT_INT_NE(feof(out), 0);
	ASSERT_SIZE_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(strstr(tmp, "12 34 56 78"), ರಿಕ್ತ);
	fclose(out);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtob16(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ *p;

	TEST_START("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_STRING_EQ(p, "12345678");
	ಮುಕ್ತ(p);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtob64_string(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ *p;

	TEST_START("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_STRING_EQ(p, "EQ==");
	ಮುಕ್ತ(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_STRING_EQ(p, "ESI=");
	ಮುಕ್ತ(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_STRING_EQ(p, "ESIz");
	ಮುಕ್ತ(p);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, ರಿಕ್ತ), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_SIZE_T_EQ(strlen(p), ((8191 + 2) / 3) * 4);
	ಮುಕ್ತ(p);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_b64tod(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;

	TEST_START("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dup_string(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ *p;

	TEST_START("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_SIZE_T_EQ(strlen(p), 0);
	ಮುಕ್ತ(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", strlen("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_SIZE_T_EQ(strlen(p), strlen("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ಮುಕ್ತ(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ರಿಕ್ತ);
	ASSERT_SIZE_T_EQ(strlen(p), strlen("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ಮುಕ್ತ(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", strlen("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, ರಿಕ್ತ);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_cmp(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ ಸಂದೇಶ[] = "imploring ping silence ping over";

	TEST_START("sshbuf_cmp");
	p1 = sshbuf_from(ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1);
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
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
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1), 0);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_find(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	ವರ್ಣ ಸಂದೇಶ[] = "imploring ping silence ping over";
	size_t sz;

	TEST_START("sshbuf_find");
	p1 = sshbuf_from(ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1);
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
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
	ASSERT_INT_EQ(sshbuf_find(p1, 0, ಸಂದೇಶ + 1, ಪರಿಮಾಣ(ಸಂದೇಶ) - 2, &sz), 0);
	ASSERT_SIZE_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_equals(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *b1, *b2;

	TEST_START("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_PTR_NE(b2, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_PTR_NE(b2, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_PTR_NE(b2, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_PTR_NE(b2, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_PTR_NE(b2, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_MESSAGE_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_DONE();

	TEST_START("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtourlb64(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *b, *b64;
	ವರ್ಣ *s;
	/* From RFC4648 */
	ಧ್ರುವ u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	ಧ್ರುವ u_char test_vec2[] = {0xff, 0xff, 0xff};
	ಧ್ರುವ u_char test_vec3[] = {0xfb};

	TEST_START("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	ASSERT_PTR_NE(b64, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	ASSERT_PTR_NE(b64, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	ಮುಕ್ತ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	ASSERT_PTR_NE(b64, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, ಪರಿಮಾಣ(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	ಮುಕ್ತ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	ASSERT_PTR_NE(b64, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, ಪರಿಮಾಣ(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "____");
	ಮುಕ್ತ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();

	TEST_START("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	ASSERT_PTR_NE(b64, ರಿಕ್ತ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, ಪರಿಮಾಣ(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ರಿಕ್ತ);
	ASSERT_STRING_EQ(s, "-w");
	ಮುಕ್ತ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_DONE();
}

ಶೂನ್ಯ
sshbuf_misc_tests(ಶೂನ್ಯ)
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

