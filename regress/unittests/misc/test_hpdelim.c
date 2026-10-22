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
	حرف *orig, *str, *cp, *پورٽ;

#وصف_ڪريو شروعات_STRING(x)	orig = str = xstrdup(x)
#وصف_ڪريو پورو_STRING()	حرر(orig)

	TEST_شروعات("hpdelim host only");
	شروعات_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("hpdelim :port");
	شروعات_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, عدم);
	پورٽ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٽ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("hpdelim host:port");
	شروعات_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, عدم);
	پورٽ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٽ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("hpdelim [host]:port");
	شروعات_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, عدم);
	پورٽ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٽ, "1234");
	ASSERT_PTR_EQ(str, عدم);
	پورو_STRING();
	TEST_پورو();

	TEST_شروعات("hpdelim missing ] error");
	شروعات_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, عدم);
	پورو_STRING();
	TEST_پورو();

}
