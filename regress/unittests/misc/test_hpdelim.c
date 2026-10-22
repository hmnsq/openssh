/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
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
#ضمن "xmalloc.h"

فراغ test_hpdelim(فراغ);

فراغ
test_hpdelim(فراغ)
{
	حرف *orig, *str, *cp, *port;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	حرر(orig)

	TEST_START("hpdelim host only");
	START_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, عدم);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim :port");
	START_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, عدم);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, عدم);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim host:port");
	START_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, عدم);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, عدم);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim [host]:port");
	START_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, عدم);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, عدم);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim missing ] error");
	START_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	DONE_STRING();
	TEST_DONE();

}
