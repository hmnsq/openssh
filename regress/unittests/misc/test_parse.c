/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
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

ಶೂನ್ಯ test_parse(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_parse(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ port;
	ವರ್ಣ *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = ರಿಕ್ತ;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	ಮುಕ್ತ(user); ಮುಕ್ತ(host); ಮುಕ್ತ(path);
	TEST_DONE();
}
