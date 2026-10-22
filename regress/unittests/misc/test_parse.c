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
	صحيح پورٽ;
	حرف *user, *host, *رستو;

	TEST_شروعات("misc_parse_user_host_path");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_user_host_رستو("someuser@some.host:some/path",
	    &user, &host, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(رستو, "some/path");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();

	TEST_شروعات("misc_parse_user_ipv4_path");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_user_host_رستو("someuser@1.22.33.144:some/path",
	    &user, &host, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستو, "some/path");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();

	TEST_شروعات("misc_parse_user_[ipv4]_path");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_user_host_رستو("someuser@[1.22.33.144]:some/path",
	    &user, &host, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستو, "some/path");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();

	TEST_شروعات("misc_parse_user_[ipv4]_nopath");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_user_host_رستو("someuser@[1.22.33.144]:",
	    &user, &host, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(رستو, ".");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();

	TEST_شروعات("misc_parse_user_ipv6_path");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_user_host_رستو("someuser@[::1]:some/path",
	    &user, &host, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(رستو, "some/path");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();

	TEST_شروعات("misc_parse_uri");
	user = host = رستو = عدم;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &پورٽ, &رستو), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(پورٽ, 22);
	ASSERT_STRING_EQ(رستو, "some/path");
	حرر(user); حرر(host); حرر(رستو);
	TEST_پورو();
}
