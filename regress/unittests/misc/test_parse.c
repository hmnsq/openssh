/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
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

ശൂന്യം test_parse(ശൂന്യം);

ശൂന്യം
test_parse(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ port;
	അക്ഷരം *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = ശൂന്യ;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	സ്വതന്ത്രം(user); സ്വതന്ത്രം(host); സ്വതന്ത്രം(path);
	TEST_DONE();
}
