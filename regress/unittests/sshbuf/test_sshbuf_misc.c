/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਖਾਲੀ sshbuf_misc_tests(ਖਾਲੀ);

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_dump(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ tmp[512];
	FILE *ਬਾਹਰਲਾ;
	ਮਾਪ_t sz;

	TEST_ਸ਼ੁਰੂ("sshbuf_dump");
	ਬਾਹਰਲਾ = tmpfile();
	ASSERT_PTR_NE(ਬਾਹਰਲਾ, ਨਿਰਾ);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, ਬਾਹਰਲਾ);
	fflush(ਬਾਹਰਲਾ);
	rewind(ਬਾਹਰਲਾ);
	sz = fread(tmp, 1, ਆਕਾਰ(tmp), ਬਾਹਰਲਾ);
	ASSERT_INT_EQ(ferror(ਬਾਹਰਲਾ), 0);
	ASSERT_INT_NE(feof(ਬਾਹਰਲਾ), 0);
	ASSERT_ਮਾਪ_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(ਲੜੀ_ਖੋਜ(tmp, "12 34 56 78"), ਨਿਰਾ);
	fclose(ਬਾਹਰਲਾ);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_dtob16(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ *p;

	TEST_ਸ਼ੁਰੂ("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_STRING_EQ(p, "12345678");
	ਮੁਕਤ(p);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_dtob64_string(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ *p;

	TEST_ਸ਼ੁਰੂ("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_STRING_EQ(p, "EQ==");
	ਮੁਕਤ(p);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_STRING_EQ(p, "ESI=");
	ਮੁਕਤ(p);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_STRING_EQ(p, "ESIz");
	ਮੁਕਤ(p);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, ਨਿਰਾ), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_EQ(ਲੜੀ_ਲੰਬਾਈ(p), ((8191 + 2) / 3) * 4);
	ਮੁਕਤ(p);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_b64tod(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;

	TEST_ਸ਼ੁਰੂ("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_dup_string(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ *p;

	TEST_ਸ਼ੁਰੂ("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_EQ(ਲੜੀ_ਲੰਬਾਈ(p), 0);
	ਮੁਕਤ(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", ਲੜੀ_ਲੰਬਾਈ("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_EQ(ਲੜੀ_ਲੰਬਾਈ(p), ਲੜੀ_ਲੰਬਾਈ("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ਮੁਕਤ(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_EQ(ਲੜੀ_ਲੰਬਾਈ(p), ਲੜੀ_ਲੰਬਾਈ("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ਮੁਕਤ(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", ਲੜੀ_ਲੰਬਾਈ("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, ਨਿਰਾ);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_cmp(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ ਸੁਨੇਹਾ[] = "imploring ping silence ping over";

	TEST_ਸ਼ੁਰੂ("sshbuf_cmp");
	p1 = sshbuf_from(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1);
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "i", 1), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "j", 1), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "imploring", 9), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "implored", 9), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ping", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ring", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "over", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "rove", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "overt", 5),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 32, "ping", 4),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 1000, "silence", 7),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1), 0);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_ਲੱਭੋ(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅੱਖਰ ਸੁਨੇਹਾ[] = "imploring ping silence ping over";
	ਮਾਪ_t sz;

	TEST_ਸ਼ੁਰੂ("sshbuf_find");
	p1 = sshbuf_from(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1);
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 0, "i", 1, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 3, "ping", 4, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 11, "ping", 4, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 20, "over", 4, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 28, "over", 4, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 28, "overt", 5, &sz),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 32, "ping", 4, &sz),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ਲੱਭੋ(p1, 0, ਸੁਨੇਹਾ + 1, ਆਕਾਰ(ਸੁਨੇਹਾ) - 2, &sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_equals(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *b1, *b2;

	TEST_ਸ਼ੁਰੂ("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_PTR_NE(b2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_PTR_NE(b2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_PTR_NE(b2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_PTR_NE(b2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_PTR_NE(b2, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
test_sshbuf_dtourlb64(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *b, *b64;
	ਅੱਖਰ *s;
	/* From RFC4648 */
	ਅਚਲ u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	ਅਚਲ u_char test_vec2[] = {0xff, 0xff, 0xff};
	ਅਚਲ u_char test_vec3[] = {0xfb};

	TEST_ਸ਼ੁਰੂ("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_PTR_NE(b64, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_PTR_NE(b64, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	ਮੁਕਤ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_PTR_NE(b64, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, ਆਕਾਰ(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	ਮੁਕਤ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_PTR_NE(b64, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, ਆਕਾਰ(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "____");
	ਮੁਕਤ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	ASSERT_PTR_NE(b64, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, ਆਕਾਰ(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ਨਿਰਾ);
	ASSERT_STRING_EQ(s, "-w");
	ਮੁਕਤ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ਪੂਰਾ();
}

ਖਾਲੀ
sshbuf_misc_tests(ਖਾਲੀ)
{
	test_sshbuf_dump();
	test_sshbuf_dtob16();
	test_sshbuf_dtob64_string();
	test_sshbuf_b64tod();
	test_sshbuf_dup_string();
	test_sshbuf_cmp();
	test_sshbuf_ਲੱਭੋ();
	test_sshbuf_equals();
	test_sshbuf_dtourlb64();
}

