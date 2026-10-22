/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
 *
 * Placed in the public domain.
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "xmalloc.h"

ശൂന്യം test_hpdelim(ശൂന്യം);

ശൂന്യം
test_hpdelim(ശൂന്യം)
{
	അക്ഷരം *orig, *str, *cp, *port;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	സ്വതന്ത്രം(orig)

	TEST_START("hpdelim host only");
	START_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, ശൂന്യ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim :port");
	START_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, ശൂന്യ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ശൂന്യ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim host:port");
	START_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, ശൂന്യ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ശൂന്യ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim [host]:port");
	START_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, ശൂന്യ);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, ശൂന്യ);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim missing ] error");
	START_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, ശൂന്യ);
	DONE_STRING();
	TEST_DONE();

}
