/* 	$OpenBSD: test_expand.c,v 1.4 2025/09/15 03:00:22 djm Exp $ */
/*
 * Regress test for misc string expansion functions.
 *
 * Placed in the public domain.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "log.h"
#समावेश "misc.h"

व्योम test_expand(व्योम);

व्योम
test_expand(व्योम)
{
	पूर्णांक parseerr;
	अक्षर *ret;

	TEST_START("dollar_expand");
	ASSERT_INT_EQ(setenv("FOO", "bar", 1), 0);
	ASSERT_INT_EQ(setenv("BAR", "baz", 1), 0);
	(व्योम)unsetenv("BAZ");
#घोषणा ASSERT_DOLLAR_EQ(x, y) करो { \
	अक्षर *str = dollar_expand(शून्य, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	मुक्त(str); \
} जबतक(0)
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
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, शून्य); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_DONE();

	TEST_START("percent_expand");
#घोषणा CHECK_ONE(val, expect) \
	ASSERT_STRING_EQ(val, expect); \
	मुक्त(val);
	ret = percent_expand("%%", "%h", "foo", शून्य);
	CHECK_ONE(ret, "%");
	ret = percent_expand("%h", "h", "foo", शून्य);
	CHECK_ONE(ret, "foo");
	ret = percent_expand("%h ", "h", "foo", शून्य);
	CHECK_ONE(ret, "foo ");
	ret = percent_expand(" %h", "h", "foo", शून्य);
	CHECK_ONE(ret, " foo");
	ret = percent_expand(" %h ", "h", "foo", शून्य);
	CHECK_ONE(ret, " foo ");
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", शून्य);
	CHECK_ONE(ret, " foobar ");
	TEST_DONE();

	TEST_START("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", शून्य);
	CHECK_ONE(ret, "foobar");
#अघोषित CHECK_ONE
	TEST_DONE();
}
