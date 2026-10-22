/* 	$OpenBSD: test_hpdelim.c,v 1.2 2022/02/06 22:58:33 dtucker Exp $ */
/*
 * Regress test for misc hpdelim() and co
 *
 * Placed in the public domain.
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "xmalloc.h"

வெறுமை test_hpdelim(வெறுமை);

வெறுமை
test_hpdelim(வெறுமை)
{
	எழுத்து *orig, *str, *cp, *port;

#define START_STRING(x)	orig = str = xstrdup(x)
#define DONE_STRING()	விடுவி(orig)

	TEST_START("hpdelim host only");
	START_STRING("host");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_EQ(str, வெற்று);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim :port");
	START_STRING(":1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "");
	ASSERT_PTR_NE(str, வெற்று);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, வெற்று);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim host:port");
	START_STRING("host:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "host");
	ASSERT_PTR_NE(str, வெற்று);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, வெற்று);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim [host]:port");
	START_STRING("[::1]:1234");
	cp = hpdelim(&str);
	ASSERT_STRING_EQ(cp, "[::1]");
	ASSERT_PTR_NE(str, வெற்று);
	port = hpdelim(&str);
	ASSERT_STRING_EQ(port, "1234");
	ASSERT_PTR_EQ(str, வெற்று);
	DONE_STRING();
	TEST_DONE();

	TEST_START("hpdelim missing ] error");
	START_STRING("[::1:1234");
	cp = hpdelim(&str);
	ASSERT_PTR_EQ(cp, வெற்று);
	DONE_STRING();
	TEST_DONE();

}
