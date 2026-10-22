/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
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
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಶೂನ್ಯ test_hpdelim(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_hpdelim(ಶೂನ್ಯ)
{
	ವರ್ಣ *orig, *str, *cp, *port;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	ಮುಕ್ತ(orig)

	TEST_START("hpdelim host only");
	START_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, ರಿಕ್ತ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim :port");
	START_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, ರಿಕ್ತ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ರಿಕ್ತ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim host:port");
	START_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, ರಿಕ್ತ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ರಿಕ್ತ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim [host]:port");
	START_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, ರಿಕ್ತ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ರಿಕ್ತ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim missing ] error");
	START_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, ರಿಕ್ತ);
	DONE_STRING();
	TEST_DONE();

}
