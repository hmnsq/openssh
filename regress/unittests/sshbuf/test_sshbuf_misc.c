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
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ tmp[512];
	FILE *ಹೊರಹೋಗು;
	ಗಾತ್ರ_t sz;

	TEST_ಆರಂಭ("sshbuf_dump");
	ಹೊರಹೋಗು = tmpfile();
	ASSERT_PTR_NE(ಹೊರಹೋಗು, ಖಾಲಿ);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	sshbuf_dump(p1, ಹೊರಹೋಗು);
	fflush(ಹೊರಹೋಗು);
	rewind(ಹೊರಹೋಗು);
	sz = fread(tmp, 1, ಗಾತ್ರ(tmp), ಹೊರಹೋಗು);
	ASSERT_INT_EQ(ferror(ಹೊರಹೋಗು), 0);
	ASSERT_INT_NE(feof(ಹೊರಹೋಗು), 0);
	ASSERT_ಗಾತ್ರ_T_GT(sz, 0);
	tmp[sz] = '\0';
	ASSERT_PTR_NE(ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(tmp, "12 34 56 78"), ಖಾಲಿ);
	fclose(ಹೊರಹೋಗು);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtob16(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ *p;

	TEST_ಆರಂಭ("sshbuf_dtob16");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	p = sshbuf_dtob16(p1);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_STRING_EQ(p, "12345678");
	ಬಿಡುಗಡೆ(p);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtob64_string(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ *p;

	TEST_ಆರಂಭ("sshbuf_dtob64_string len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_STRING_EQ(p, "EQ==");
	ಬಿಡುಗಡೆ(p);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtob64_string len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_STRING_EQ(p, "ESI=");
	ಬಿಡುಗಡೆ(p);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtob64_string len 3");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x11), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x22), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x33), 0);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_STRING_EQ(p, "ESIz");
	ಬಿಡುಗಡೆ(p);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtob64_string len 8191");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 8192, ಖಾಲಿ), 0);
	bzero(sshbuf_mutable_ptr(p1), 8192);
	p = sshbuf_dtob64_string(p1, 0);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p), ((8191 + 2) / 3) * 4);
	ಬಿಡುಗಡೆ(p);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_b64tod(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;

	TEST_ಆರಂಭ("sshbuf_b64tod len 1");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A=="), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), 1);
	ASSERT_U8_EQ(*sshbuf_ptr(p1), 0xd0);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_b64tod len 2");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A8="), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), 2);
	ASSERT_U16_EQ(PEEK_U16(sshbuf_ptr(p1)), 0xd00f);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_b64tod len 4");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_b64tod(p1, "0A/QDw=="), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), 0xd00fd00f);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dup_string(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ *p;

	TEST_ಆರಂಭ("sshbuf_dup_string");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	/* Check empty buffer */
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p), 0);
	ಬಿಡುಗಡೆ(p);
	/* Check buffer with string */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad1", ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("quad1")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p), ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ಬಿಡುಗಡೆ(p);
	/* Check buffer with terminating nul */
	ASSERT_INT_EQ(sshbuf_put(p1, "\0", 1), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_NE(p, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p), ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("quad1"));
	ASSERT_STRING_EQ(p, "quad1");
	ಬಿಡುಗಡೆ(p);
	/* Check buffer with data after nul (expect failure) */
	ASSERT_INT_EQ(sshbuf_put(p1, "quad2", ಅಕ್ಷರಸರಣಿ_ಉದ್ದ("quad2")), 0);
	p = sshbuf_dup_string(p1);
	ASSERT_PTR_EQ(p, ಖಾಲಿ);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_cmp(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ ಸಂದೇಶ[] = "imploring ping silence ping over";

	TEST_ಆರಂಭ("sshbuf_cmp");
	p1 = sshbuf_from(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1);
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "i", 1), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "j", 1), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "imploring", 9), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, "implored", 9), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ping", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 10, "ring", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "over", 4), 0);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "rove", 4), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 28, "overt", 5),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 32, "ping", 4),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 1000, "silence", 7),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_cmp(p1, 0, ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1), 0);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_ಕಂಡುಹಿಡಿ(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	ಅಕ್ಷರ ಸಂದೇಶ[] = "imploring ping silence ping over";
	ಗಾತ್ರ_t sz;

	TEST_ಆರಂಭ("sshbuf_find");
	p1 = sshbuf_from(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1);
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 0, "i", 1, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 0, "j", 1, &sz), SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 0, "imploring", 9, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 0);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 0, "implored", 9, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 3, "ping", 4, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 10);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 11, "ping", 4, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 23);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 20, "over", 4, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 28, "over", 4, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 28);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 28, "rove", 4, &sz),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 28, "overt", 5, &sz),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 32, "ping", 4, &sz),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 1000, "silence", 7, &sz),
	    SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_ಕಂಡುಹಿಡಿ(p1, 0, ಸಂದೇಶ + 1, ಗಾತ್ರ(ಸಂದೇಶ) - 2, &sz), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sz, 1);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_equals(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *b1, *b2;

	TEST_ಆರಂಭ("sshbuf_equals identical");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_PTR_NE(b2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_equals different content");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_PTR_NE(b2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "world", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_INVALID_FORMAT);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_equals different length");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_PTR_NE(b2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_put(b2, "hell", 4), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_equals empty buffers");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_PTR_NE(b2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), 0);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_equals one empty buffer");
	b1 = sshbuf_new();
	b2 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_PTR_NE(b2, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b2), SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	sshbuf_free(b1);
	sshbuf_free(b2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_equals buffer to self");
	b1 = sshbuf_new();
	ASSERT_PTR_NE(b1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b1, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_equals(b1, b1), 0);
	sshbuf_free(b1);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_sshbuf_dtourlb64(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *b, *b64;
	ಅಕ್ಷರ *s;
	/* From RFC4648 */
	ಸ್ಥಿರಾಂಕ u_char test_vec1[] = {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e};
	ಸ್ಥಿರಾಂಕ u_char test_vec2[] = {0xff, 0xff, 0xff};
	ಸ್ಥಿರಾಂಕ u_char test_vec3[] = {0xfb};

	TEST_ಆರಂಭ("sshbuf_dtourlb64 empty");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_PTR_NE(b64, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(b64), 0);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtourlb64 no special chars");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_PTR_NE(b64, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b, "hello", 5), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "aGVsbG8");
	ಬಿಡುಗಡೆ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtourlb64 with '+' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_PTR_NE(b64, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec1, ಗಾತ್ರ(test_vec1)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "FPucA9l-");
	ಬಿಡುಗಡೆ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtourlb64 with '/' char");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_PTR_NE(b64, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec2, ಗಾತ್ರ(test_vec2)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "____");
	ಬಿಡುಗಡೆ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_dtourlb64 with padding removed");
	b = sshbuf_new();
	b64 = sshbuf_new();
	ASSERT_PTR_NE(b, ಖಾಲಿ);
	ASSERT_PTR_NE(b64, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(b, test_vec3, ಗಾತ್ರ(test_vec3)), 0);
	ASSERT_INT_EQ(sshbuf_dtourlb64(b, b64, 0), 0);
	s = sshbuf_dup_string(b64);
	ASSERT_PTR_NE(s, ಖಾಲಿ);
	ASSERT_STRING_EQ(s, "-w");
	ಬಿಡುಗಡೆ(s);
	sshbuf_free(b);
	sshbuf_free(b64);
	TEST_ಮುಗಿದ();
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
	test_sshbuf_ಕಂಡುಹಿಡಿ();
	test_sshbuf_equals();
	test_sshbuf_dtourlb64();
}

