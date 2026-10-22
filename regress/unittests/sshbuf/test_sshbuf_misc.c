/* 	$OpenBSD: test_sshbuf_misc.c,v 1.7 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "sshbuf.h"
#شامل "ssherr.h"

خالی sshbuf_misc_tests(خالی);

ساکن خالی
test_sshbuf_dump(خالی)
{
	ساخت sshbuf *p1;
	حرف tmp[512];
	FILE *برآمد;
	سائز_t sz;

	TEST_آغاز("sshbuf_dump");
	برآمد = tmpfile();
	ASSERT_PTR_NE(برآمد, تہی);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, برآمد);
	fflush(برآمد);
	rewind(برآمد);
	sz = fread(tmp, 1, حجم(tmp), برآمد);
	ASSERT_INT_EQ(ferror(برآمد), 0);
	ASSERT_INT_NE(feof(برآمد), 0);
	ASSERT_سائز_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(لڑی_تلاش(tmp, "12 34 56 78"), تہی);
	fclose(برآمد);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_dtob16(خالی)
{
	ساخت sshbuf *p1;
	حرف *p;

	TEST_آغاز("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_STRING_EQ(p, "12345678");
	آزاد(p);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_dtob64_string(خالی)
{
	ساخت sshbuf *p1;
	حرف *p;

	TEST_آغاز("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_STRING_EQ(p, "EQ==");
	آزاد(p);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_STRING_EQ(p, "ESI=");
	آزاد(p);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_STRING_EQ(p, "ESIz");
	آزاد(p);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, تہی), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_سائز_T_EQ(لڑی_لمبائی(p), ((8191 + 2) / 3) * 4);
	آزاد(p);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_b64tod(خالی)
{
	ساخت sshbuf *p1;

	TEST_آغاز("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_dup_string(خالی)
{
	ساخت sshbuf *p1;
	حرف *p;

	TEST_آغاز("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_سائز_T_EQ(لڑی_لمبائی(p), 0);
	آزاد(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", لڑی_لمبائی("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_سائز_T_EQ(لڑی_لمبائی(p), لڑی_لمبائی("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	آزاد(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, تہی);
	ASSERT_سائز_T_EQ(لڑی_لمبائی(p), لڑی_لمبائی("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	آزاد(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", لڑی_لمبائی("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, تہی);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_cmp(خالی)
{
	ساخت sshbuf *p1;
	حرف پیغام[] = "imploring ping silence ping over";

	TEST_آغاز("sshbuf_cmp");
	p1 = sshbuf_from(پیغام, حجم(پیغام) - 1);
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "i", 1), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "j", 1), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "imploring", 9), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "implored", 9), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ping", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ring", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "over", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "rove", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "overt", 5),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 32, "ping", 4),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 1000, "silence", 7),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, پیغام, حجم(پیغام) - 1), 0);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_ڈھونڈو(خالی)
{
	ساخت sshbuf *p1;
	حرف پیغام[] = "imploring ping silence ping over";
	سائز_t sz;

	TEST_آغاز("sshbuf_find");
	p1 = sshbuf_from(پیغام, حجم(پیغام) - 1);
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 0, "i", 1, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 3, "ping", 4, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 11, "ping", 4, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 20, "over", 4, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 28, "over", 4, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 28, "overt", 5, &sz),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 32, "ping", 4, &sz),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ڈھونڈو(p1, 0, پیغام + 1, حجم(پیغام) - 2, &sz), 0);
	ASSERT_سائز_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_equals(خالی)
{
	ساخت sshbuf *b1, *b2;

	TEST_آغاز("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_PTR_NE(b2, تہی);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_مکمل();

	TEST_آغاز("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_PTR_NE(b2, تہی);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_مکمل();

	TEST_آغاز("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_PTR_NE(b2, تہی);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_پیغام_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_مکمل();

	TEST_آغاز("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_PTR_NE(b2, تہی);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_مکمل();

	TEST_آغاز("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_PTR_NE(b2, تہی);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_پیغام_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_مکمل();

	TEST_آغاز("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, تہی);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_مکمل();
}

ساکن خالی
test_sshbuf_dtourlb64(خالی)
{
	ساخت sshbuf *b, *b64;
	حرف *s;
	/* From RFC4648 */
	ثابت u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	ثابت u_char test_vec2[] = {0xff, 0xff, 0xff};
	ثابت u_char test_vec3[] = {0xfb};

	TEST_آغاز("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_PTR_NE(b64, تہی);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_PTR_NE(b64, تہی);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	آزاد(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_PTR_NE(b64, تہی);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, حجم(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	آزاد(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_PTR_NE(b64, تہی);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, حجم(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "____");
	آزاد(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_مکمل();

	TEST_آغاز("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, تہی);
	ASSERT_PTR_NE(b64, تہی);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, حجم(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, تہی);
	ASSERT_STRING_EQ(s, "-w");
	آزاد(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_مکمل();
}

خالی
sshbuf_misc_tests(خالی)
{
	test_sshbuf_dump();
	test_sshbuf_dtob16();
	test_sshbuf_dtob64_string();
	test_sshbuf_b64tod();
	test_sshbuf_dup_string();
	test_sshbuf_cmp();
	test_sshbuf_ڈھونڈو();
	test_sshbuf_equals();
	test_sshbuf_dtourlb64();
}

