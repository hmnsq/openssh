/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
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

வெறுமை test_parse(வெறுமை);

வெறுமை
test_parse(வெறுமை)
{
	முழு port;
	எழுத்து *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = வெற்று;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	விடுவி(user); விடுவி(host); விடுவி(path);
	TEST_DONE();
}
