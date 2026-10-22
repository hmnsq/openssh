/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
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

تهی test_parse(تهی);

تهی
test_parse(تهی)
{
	صحیح port;
	نویسه *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = پوچ;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	آزاد(user); آزاد(host); آزاد(path);
	TEST_DONE();
}
