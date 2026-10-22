/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
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

ಶೂನ್ಯ test_hpdelim(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_hpdelim(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *orig, *str, *cp, *ಪೋರ್ಟ್;

#ವ್ಯಾಖ್ಯಾನಿಸು ಆರಂಭ_STRING(x)	orig = str = xstrdup(x)
#ವ್ಯಾಖ್ಯಾನಿಸು ಮುಗಿದ_STRING()	ಬಿಡುಗಡೆ(orig)

	TEST_ಆರಂಭ("hpdelim host only");
	ಆರಂಭ_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hpdelim :port");
	ಆರಂಭ_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, ಖಾಲಿ);
	ಪೋರ್ಟ್ = hpdelim(&str);
	ASSERT_STRING_EQ(ಪೋರ್ಟ್, "1234");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hpdelim host:port");
	ಆರಂಭ_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, ಖಾಲಿ);
	ಪೋರ್ಟ್ = hpdelim(&str);
	ASSERT_STRING_EQ(ಪೋರ್ಟ್, "1234");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hpdelim [host]:port");
	ಆರಂಭ_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, ಖಾಲಿ);
	ಪೋರ್ಟ್ = hpdelim(&str);
	ASSERT_STRING_EQ(ಪೋರ್ಟ್, "1234");
	ASSERT_PTR_EQ(str, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hpdelim missing ] error");
	ಆರಂಭ_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, ಖಾಲಿ);
	ಮುಗಿದ_STRING();
	TEST_ಮುಗಿದ();

}
