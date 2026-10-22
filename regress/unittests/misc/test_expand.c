/* 	$OpenBSD: test_expand.c,v 1.4 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for misc string expansion functions.
 *
 * Placed in the public domain.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"

خالی test_expand(خالی);

خالی
test_expand(خالی)
{
	صحیح parseerr;
	حرف *ret;

	TEST_آغاز("dollar_expand");
	ASSERT_INT_EQ(setenv("FOO", "bar", 1), 0);
	ASSERT_INT_EQ(setenv("BAR", "baz", 1), 0);
	(خالی)unsetenv("BAZ");
#تعریف_کرو ASSERT_DOLLAR_EQ(x, y) کرو { \
	حرف *str = dollar_expand(تہی, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	آزاد(str); \
} جب(0)
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
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, تہی); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_مکمل();

	TEST_آغاز("percent_expand");
#تعریف_کرو CHECK_ONE(val, expect) \
	ASSERT_STRING_EQ(val, expect); \
	آزاد(val);
	ret = percent_expand("%%", "%h", "foo", تہی);
	CHECK_ONE(ret, "%");
	ret = percent_expand("%h", "h", "foo", تہی);
	CHECK_ONE(ret, "foo");
	ret = percent_expand("%h ", "h", "foo", تہی);
	CHECK_ONE(ret, "foo ");
	ret = percent_expand(" %h", "h", "foo", تہی);
	CHECK_ONE(ret, " foo");
	ret = percent_expand(" %h ", "h", "foo", تہی);
	CHECK_ONE(ret, " foo ");
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", تہی);
	CHECK_ONE(ret, " foobar ");
	TEST_مکمل();

	TEST_آغاز("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", تہی);
	CHECK_ONE(ret, "foobar");
#تعریف_منسوخ CHECK_ONE
	TEST_مکمل();
}
