/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
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
#شامل "xmalloc.h"

خالی test_hpdelim(خالی);

خالی
test_hpdelim(خالی)
{
	حرف *orig, *str, *cp, *پورٹ;

#تعریف_کرو آغاز_STRING(x)	orig = str = xstrdup(x)
#تعریف_کرو مکمل_STRING()	آزاد(orig)

	TEST_آغاز("hpdelim host only");
	آغاز_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("hpdelim :port");
	آغاز_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, تہی);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("hpdelim host:port");
	آغاز_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, تہی);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("hpdelim [host]:port");
	آغاز_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, تہی);
	پورٹ = hpdelim(&str);
	ASSERT_STRING_EQ(پورٹ, "1234");
	ASSERT_PTR_EQ(str, تہی);
	مکمل_STRING();
	TEST_مکمل();

	TEST_آغاز("hpdelim missing ] error");
	آغاز_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, تہی);
	مکمل_STRING();
	TEST_مکمل();

}
