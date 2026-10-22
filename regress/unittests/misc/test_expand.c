/* 	$OpenBSD: test_expand.c,v 1.4 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for misc string expansion functions.
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

ਖਾਲੀ test_expand(ਖਾਲੀ);

ਖਾਲੀ
test_expand(ਖਾਲੀ)
{
	ਪੂਰਨ parseerr;
	ਅੱਖਰ *ret;

	TEST_ਸ਼ੁਰੂ("dollar_expand");
	ASSERT_INT_EQ(setenv("FOO", "bar", 1), 0);
	ASSERT_INT_EQ(setenv("BAR", "baz", 1), 0);
	(ਖਾਲੀ)unsetenv("BAZ");
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOLLAR_EQ(x, y) ਕਰੋ { \
	ਅੱਖਰ *str = dollar_expand(ਨਿਰਾ, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	ਮੁਕਤ(str); \
} ਜਦੋਂ(0)
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
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, ਨਿਰਾ); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("percent_expand");
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHECK_ONE(val, expect) \
	ASSERT_STRING_EQ(val, expect); \
	ਮੁਕਤ(val);
	ret = percent_expand("%%", "%h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, "%");
	ret = percent_expand("%h", "h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, "foo");
	ret = percent_expand("%h ", "h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, "foo ");
	ret = percent_expand(" %h", "h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, " foo");
	ret = percent_expand(" %h ", "h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, " foo ");
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", ਨਿਰਾ);
	CHECK_ONE(ret, " foobar ");
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", ਨਿਰਾ);
	CHECK_ONE(ret, "foobar");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CHECK_ONE
	TEST_ਪੂਰਾ();
}
