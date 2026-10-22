/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
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

فراغ test_parse(فراغ);

فراغ
test_parse(فراغ)
{
	صحيح پورٹ;
	حرف *user, *host, *رستہ;

	TEST_شروع("misc_parse_user_host_path");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_user_host_رستہ("someuser@some.host:some/path",
	    &user, &host, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(رستہ, "some/path");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();

	TEST_شروع("misc_parse_user_ipv4_path");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_user_host_رستہ("someuser@1.22.33.144:some/path",
	    &user, &host, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستہ, "some/path");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();

	TEST_شروع("misc_parse_user_[ipv4]_path");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_user_host_رستہ("someuser@[1.22.33.144]:some/path",
	    &user, &host, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستہ, "some/path");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();

	TEST_شروع("misc_parse_user_[ipv4]_nopath");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_user_host_رستہ("someuser@[1.22.33.144]:",
	    &user, &host, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستہ, ".");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();

	TEST_شروع("misc_parse_user_ipv6_path");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_user_host_رستہ("someuser@[::1]:some/path",
	    &user, &host, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(رستہ, "some/path");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();

	TEST_شروع("misc_parse_uri");
	user = host = رستہ = عدم;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &پورٹ, &رستہ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(پورٹ, 22);
	ASSERT_STRING_EQ(رستہ, "some/path");
	حرر(user); حرر(host); حرر(رستہ);
	TEST_پورا();
}
