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

خالی test_parse(خالی);

خالی
test_parse(خالی)
{
	صحیح پورٹ;
	حرف *user, *host, *راستہ;

	TEST_آغاز("misc_parse_user_host_path");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_user_host_راستہ("someuser@some.host:some/path",
	    &user, &host, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(راستہ, "some/path");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();

	TEST_آغاز("misc_parse_user_ipv4_path");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_user_host_راستہ("someuser@1.22.33.144:some/path",
	    &user, &host, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(راستہ, "some/path");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();

	TEST_آغاز("misc_parse_user_[ipv4]_path");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_user_host_راستہ("someuser@[1.22.33.144]:some/path",
	    &user, &host, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(راستہ, "some/path");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();

	TEST_آغاز("misc_parse_user_[ipv4]_nopath");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_user_host_راستہ("someuser@[1.22.33.144]:",
	    &user, &host, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(راستہ, ".");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();

	TEST_آغاز("misc_parse_user_ipv6_path");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_user_host_راستہ("someuser@[::1]:some/path",
	    &user, &host, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(راستہ, "some/path");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();

	TEST_آغاز("misc_parse_uri");
	user = host = راستہ = تہی;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &پورٹ, &راستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(پورٹ, 22);
	ASSERT_STRING_EQ(راستہ, "some/path");
	آزاد(user); آزاد(host); آزاد(راستہ);
	TEST_مکمل();
}
