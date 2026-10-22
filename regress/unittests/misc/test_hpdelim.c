/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਖਾਲੀ test_hpdelim(ਖਾਲੀ);

ਖਾਲੀ
test_hpdelim(ਖਾਲੀ)
{
	ਅੱਖਰ *orig, *str, *cp, *ਪੋਰਟ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸ਼ੁਰੂ_STRING(x)	orig = str = xstrdup(x)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੂਰਾ_STRING()	ਮੁਕਤ(orig)

	TEST_ਸ਼ੁਰੂ("hpdelim host only");
	ਸ਼ੁਰੂ_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hpdelim :port");
	ਸ਼ੁਰੂ_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, ਨਿਰਾ);
	ਪੋਰਟ = hpdelim(&str);
	ASSERT_STRING_EQ(ਪੋਰਟ, "1234");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hpdelim host:port");
	ਸ਼ੁਰੂ_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, ਨਿਰਾ);
	ਪੋਰਟ = hpdelim(&str);
	ASSERT_STRING_EQ(ਪੋਰਟ, "1234");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hpdelim [host]:port");
	ਸ਼ੁਰੂ_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, ਨਿਰਾ);
	ਪੋਰਟ = hpdelim(&str);
	ASSERT_STRING_EQ(ਪੋਰਟ, "1234");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hpdelim missing ] error");
	ਸ਼ੁਰੂ_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

}
