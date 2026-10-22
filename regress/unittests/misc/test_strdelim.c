/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
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

ਖਾਲੀ test_strdelim(ਖਾਲੀ);

ਖਾਲੀ
test_strdelim(ਖਾਲੀ)
{
	ਅੱਖਰ *orig, *str, *cp;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸ਼ੁਰੂ_STRING(x)	orig = str = xstrdup(x)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਪੂਰਾ_STRING()	ਮੁਕਤ(orig)

	TEST_ਸ਼ੁਰੂ("empty");
	ਸ਼ੁਰੂ_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("whitespace");
	ਸ਼ੁਰੂ_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("trivial");
	ਸ਼ੁਰੂ_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("trivial whitespace");
	ਸ਼ੁਰੂ_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("multi");
	ਸ਼ੁਰੂ_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("multi whitespace");
	ਸ਼ੁਰੂ_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("multi equals");
	ਸ਼ੁਰੂ_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("multi too many equals");
	ਸ਼ੁਰੂ_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("multi equals strdelimw");
	ਸ਼ੁਰੂ_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted");
	ਸ਼ੁਰੂ_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted multi");
	ਸ਼ੁਰੂ_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted multi reverse");
	ਸ਼ੁਰੂ_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("quoted multi middle");
	ਸ਼ੁਰੂ_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("badquote");
	ਸ਼ੁਰੂ_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ਨਿਰਾ);
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("oops quote");
	ਸ਼ੁਰੂ_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ਪੂਰਾ_STRING();
	TEST_ਪੂਰਾ();

}
