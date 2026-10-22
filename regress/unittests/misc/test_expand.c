/* 	$OpenBSD: test_expand.c,v 1.4 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for misc string expansion functions.
 *
 * Placed in the public domain.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "log.h"
#ضمن "misc.h"

فراغ test_expand(فراغ);

فراغ
test_expand(فراغ)
{
	صحيح parseerr;
	حرف *ret;

	TEST_شروع("dollar_expand");
	ASSERT_INT_EQ(setenv("FOO", "bar", 1), 0);
	ASSERT_INT_EQ(setenv("BAR", "baz", 1), 0);
	(فراغ)unsetenv("BAZ");
#تعریف_کن ASSERT_DOLLAR_EQ(x, y) افعل { \
	حرف *str = dollar_expand(عدم, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	حرر(str); \
} طالما(0)
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
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, عدم); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_انجامشده();

	TEST_شروع("percent_expand");
#تعریف_کن CHECK_ONE(val, expect) \
	ASSERT_STRING_EQ(val, expect); \
	حرر(val);
	ret = percent_expand("%%", "%h", "foo", عدم);
	CHECK_ONE(ret, "%");
	ret = percent_expand("%h", "h", "foo", عدم);
	CHECK_ONE(ret, "foo");
	ret = percent_expand("%h ", "h", "foo", عدم);
	CHECK_ONE(ret, "foo ");
	ret = percent_expand(" %h", "h", "foo", عدم);
	CHECK_ONE(ret, " foo");
	ret = percent_expand(" %h ", "h", "foo", عدم);
	CHECK_ONE(ret, " foo ");
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", عدم);
	CHECK_ONE(ret, " foobar ");
	TEST_انجامشده();

	TEST_شروع("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", عدم);
	CHECK_ONE(ret, "foobar");
#لغو_تعریف CHECK_ONE
	TEST_انجامشده();
}
