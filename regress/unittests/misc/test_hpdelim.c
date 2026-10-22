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
	حرف *orig, *str, *cp, *پورٹ;

#تعریف_کرو شروع_STRING(x)	orig = str = xstrdup(x)
#تعریف_کرو پورا_STRING()	حرر(orig)

	TEST_شروع("hpdelim host only");
	شروع_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, عدم);
	پورا_STRING();
	TEST_پورا();

	TEST_شروع("hpdelim :port");
	شروع_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, عدم);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورا_STRING();
	TEST_پورا();

	TEST_شروع("hpdelim host:port");
	شروع_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, عدم);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورا_STRING();
	TEST_پورا();

	TEST_شروع("hpdelim [host]:port");
	شروع_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, عدم);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورا_STRING();
	TEST_پورا();

	TEST_شروع("hpdelim missing ] error");
	شروع_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورا_STRING();
	TEST_پورا();

}
