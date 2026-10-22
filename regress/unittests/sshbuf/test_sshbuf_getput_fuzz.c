/* 	$OpenBSD: test_sshbuf_getput_fuzz.c,v 1.7 2026/03/06 06:57:33 dtucker Exp $ */
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

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/objects.h>
#समावेश <openssl/ec.h>
#पूर्ण_अगर

#समावेश "../test_helper/test_helper.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"

व्योम sshbuf_getput_fuzz_tests(व्योम);

अटल व्योम
attempt_parse_blob(u_char *blob, माप_प्रकार len)
{
	काष्ठा sshbuf *p1;
#अगर_घोषित WITH_OPENSSL
	BIGNUM *bn;
	EC_कुंजी *eck;
#पूर्ण_अगर /* WITH_OPENSSL */
	u_char *s;
	माप_प्रकार l;
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;

	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_INT_EQ(sshbuf_put(p1, blob, len), 0);
	ASSERT_INT_EQ(sshbuf_get_u8(p1, &u8), 0);
	ASSERT_INT_EQ(sshbuf_get_u16(p1, &u16), 0);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &u32), 0);
	ASSERT_INT_EQ(sshbuf_get_u64(p1, &u64), 0);
	अगर (sshbuf_get_string(p1, &s, &l) == 0) {
		bzero(s, l);
		मुक्त(s);
	}
#अगर_घोषित WITH_OPENSSL
	bn = शून्य;
	ASSERT_INT_EQ(sshbuf_get_bignum2(p1, &bn), 0);
	BN_clear_free(bn);
	eck = EC_कुंजी_new_by_curve_name(NID_X9_62_prime256v1);
	ASSERT_PTR_NE(eck, शून्य);
	ASSERT_INT_EQ(sshbuf_get_eckey(p1, eck), 0);
	EC_कुंजी_free(eck);
#पूर्ण_अगर /* WITH_OPENSSL */
	sshbuf_free(p1);
}


अटल व्योम
onerror(व्योम *fuzz)
{
	ख_लिखो(मानक_त्रुटि, "Failed during fuzz:\n");
	fuzz_dump((काष्ठा fuzz *)fuzz);
}

व्योम
sshbuf_getput_fuzz_tests(व्योम)
{
	u_char blob[] = {
		/* u8 */
		0xd0,
		/* u16 */
		0xc0, 0xde,
		/* u32 */
		0xfa, 0xce, 0xde, 0xad,
		/* u64 */
		0xfe, 0xed, 0xac, 0x1d, 0x1f, 0x1c, 0xbe, 0xef,
		/* string */
		0x00, 0x00, 0x00, 0x09,
		'O', ' ', 'G', 'o', 'r', 'g', 'o', 'n', '!',
		/* bignum2 */
		0x00, 0x00, 0x00, 0x14,
		0x00,
		0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
		0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
		0x7f, 0xff, 0x11,
		/* EC point (NIST-256 curve) */
		0x00, 0x00, 0x00, 0x41,
		0x04,
		0x0c, 0x82, 0x80, 0x04, 0x83, 0x9d, 0x01, 0x06,
		0xaa, 0x59, 0x57, 0x52, 0x16, 0x19, 0x13, 0x57,
		0x34, 0xb4, 0x51, 0x45, 0x9d, 0xad, 0xb5, 0x86,
		0x67, 0x7e, 0xf9, 0xdf, 0x55, 0x78, 0x49, 0x99,
		0x4d, 0x19, 0x6b, 0x50, 0xf0, 0xb4, 0xe9, 0x4b,
		0x3c, 0x73, 0xe3, 0xa9, 0xd4, 0xcd, 0x9d, 0xf2,
		0xc8, 0xf9, 0xa3, 0x5e, 0x42, 0xbd, 0xd0, 0x47,
		0x55, 0x0f, 0x69, 0xd8, 0x0e, 0xc2, 0x3c, 0xd4,
	};
	काष्ठा fuzz *fuzz;
	u_int fuzzers = FUZZ_1_BIT_FLIP | FUZZ_2_BIT_FLIP |
	    FUZZ_1_BYTE_FLIP | FUZZ_2_BYTE_FLIP |
	    FUZZ_TRUNCATE_START | FUZZ_TRUNCATE_END;

	अगर (test_is_fast())
		fuzzers &= ~(FUZZ_2_BYTE_FLIP|FUZZ_2_BIT_FLIP);

	TEST_START("fuzz blob parsing");
	fuzz = fuzz_begin(fuzzers, blob, माप(blob));
	TEST_ONERROR(onerror, fuzz);
	क्रम(; !fuzz_done(fuzz); fuzz_अग्र(fuzz))
		attempt_parse_blob(blob, माप(blob));
	fuzz_cleanup(fuzz);
	TEST_DONE();
	TEST_ONERROR(शून्य, शून्य);
}

