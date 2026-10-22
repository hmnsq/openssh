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
	حرف *orig, *str, *cp, *پورټ;

#تعریف_کړه پیل_STRING(x)	orig = str = xstrdup(x)
#تعریف_کړه بشپړ_STRING()	حرر(orig)

	TEST_پیل("hpdelim host only");
	پیل_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("hpdelim :port");
	پیل_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, عدم);
	پورټ = hpdelim(&str);
	ASSERT_STRING_EQ(پورټ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("hpdelim host:port");
	پیل_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, عدم);
	پورټ = hpdelim(&str);
	ASSERT_STRING_EQ(پورټ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("hpdelim [host]:port");
	پیل_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, عدم);
	پورټ = hpdelim(&str);
	ASSERT_STRING_EQ(پورټ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

	TEST_پیل("hpdelim missing ] error");
	پیل_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	بشپړ_STRING();
	TEST_بشپړ();

}
