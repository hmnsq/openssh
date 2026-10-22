/* 	$OpenBSD: test_expand.c,v 1.4 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for misc string expansion functions.
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

ಶೂನ್ಯ test_expand(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_expand(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ parseerr;
	ಅಕ್ಷರ *ret;

	TEST_ಆರಂಭ("dollar_expand");
	ASSERT_INT_EQ(setenv("FOO", "bar", 1), 0);
	ASSERT_INT_EQ(setenv("BAR", "baz", 1), 0);
	(ಶೂನ್ಯ)unsetenv("BAZ");
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOLLAR_EQ(x, y) ಮಾಡು { \
	ಅಕ್ಷರ *str = dollar_expand(ಖಾಲಿ, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	ಬಿಡುಗಡೆ(str); \
} ಆಗ(0)
	ASSERT_DOLLAR_EQ("${FOO}", "bar");
	ASSERT_DOLLAR_EQ(" ${FOO}", " bar");
	ASSERT_DOLLAR_EQ("${FOO} ", "bar ");
	ASSERT_DOLLAR_EQ(" ${FOO} ", " bar ");
	ASSERT_DOLLAR_EQ("${FOO}${BAR}", "barbaz");
	ASSERT_DOLLAR_EQ(" ${FOO} ${BAR}", " bar baz");
	ASSERT_DOLLAR_EQ("${FOO}${BAR} ", "barbaz ");
	ASSERT_DOLLAR_EQ(" ${FOO} ${BAR} ", " bar baz ");
	ASSERT_DOLLAR_EQ("$", "$");
	ASSERT_DOLLAR_EQ(" $", " $");
	ASSERT_DOLLAR_EQ("$ ", "$ ");

	/* suppress error messages for error handing tests */
	log_init("test_misc", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
	/* error checking, non existent variable */
	ret = dollar_expand(&parseerr, "a${BAZ}");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, ಖಾಲಿ); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("percent_expand");
#ವ್ಯಾಖ್ಯಾನಿಸು CHECK_ONE(val, expect) \
	ASSERT_STRING_EQ(val, expect); \
	ಬಿಡುಗಡೆ(val);
	ret = percent_expand("%%", "%h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, "%");
	ret = percent_expand("%h", "h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, "foo");
	ret = percent_expand("%h ", "h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, "foo ");
	ret = percent_expand(" %h", "h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, " foo");
	ret = percent_expand(" %h ", "h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, " foo ");
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", ಖಾಲಿ);
	CHECK_ONE(ret, " foobar ");
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", ಖಾಲಿ);
	CHECK_ONE(ret, "foobar");
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CHECK_ONE
	TEST_ಮುಗಿದ();
}
