/* 	$OpenBSD: test_strdelim.c,v 1.3 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc strdelim() and co
 *
 * Placed in the public domain.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಶೂನ್ಯ test_strdelim(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_strdelim(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *orig, *str, *cp;

#ವ್ಯಾಖ್ಯಾನಿಸು ಆರಂಭ_STRING(x)	orig = str = xstrdup(x)
#ವ್ಯಾಖ್ಯಾನಿಸು ಮುಗಿದ_STRING()	ಬಿಡುಗಡೆ(orig)

	TEST_ಆರಂಭ("empty");
	ಆರಂಭ_STRING("");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX arguable */
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("whitespace");
	ಆರಂಭ_STRING("	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_STRING_EQ(str, "");
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("trivial");
	ಆರಂಭ_STRING("blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("trivial whitespace");
	ಆರಂಭ_STRING("blob   ");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("multi");
	ಆರಂಭ_STRING("blob1 blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("multi whitespace");
	ಆರಂಭ_STRING("blob1	 	blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2  	 	");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("multi equals");
	ಆರಂಭ_STRING("blob1=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("multi too many equals");
	ಆರಂಭ_STRING("blob1==blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");	/* XXX better returning NULL early */
	ASSERT_STRING_EQ(str, "=blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");	/* XXX should (but can't) reject */
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("multi equals strdelimw");
	ಆರಂಭ_STRING("blob1=blob2");
	cp = strdelimw(&str);
	ASSERT_STRING_EQ(cp, "blob1=blob2");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	cp = strdelimw(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted");
	ಆರಂಭ_STRING("\"blob\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted multi");
	ಆರಂಭ_STRING("\"blob1\" blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted multi reverse");
	ಆರಂಭ_STRING("blob1 \"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	ASSERT_STRING_EQ(str, "\"blob2\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	ASSERT_STRING_EQ(str, "");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");	/* XXX better as NULL */
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted multi middle");
	ಆರಂಭ_STRING("blob1 \"blob2\" blob3");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob1");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob2");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob3");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("badquote");
	ಆರಂಭ_STRING("\"blob");
	cp = strdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("oops quote");
	ಆರಂಭ_STRING("\"blob\\\"");
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "blob\\");	/* XXX wrong */
	cp = strdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

}
