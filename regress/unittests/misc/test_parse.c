/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
 *
 * Placed in the public domain.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

ਖਾਲੀ test_parse(ਖਾਲੀ);

ਖਾਲੀ
test_parse(ਖਾਲੀ)
{
	ਪੂਰਨ ਪੋਰਟ;
	ਅੱਖਰ *user, *host, *ਰਸਤਾ;

	TEST_ਸ਼ੁਰੂ("misc_parse_user_host_path");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_user_host_ਰਸਤਾ("someuser@some.host:some/path",
	    &user, &host, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(ਰਸਤਾ, "some/path");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_parse_user_ipv4_path");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_user_host_ਰਸਤਾ("someuser@1.22.33.144:some/path",
	    &user, &host, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(ਰਸਤਾ, "some/path");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_parse_user_[ipv4]_path");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_user_host_ਰਸਤਾ("someuser@[1.22.33.144]:some/path",
	    &user, &host, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(ਰਸਤਾ, "some/path");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_parse_user_[ipv4]_nopath");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_user_host_ਰਸਤਾ("someuser@[1.22.33.144]:",
	    &user, &host, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(ਰਸਤਾ, ".");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_parse_user_ipv6_path");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_user_host_ਰਸਤਾ("someuser@[::1]:some/path",
	    &user, &host, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(ਰਸਤਾ, "some/path");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("misc_parse_uri");
	user = host = ਰਸਤਾ = ਨਿਰਾ;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &ਪੋਰਟ, &ਰਸਤਾ), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(ਪੋਰਟ, 22);
	ASSERT_STRING_EQ(ਰਸਤਾ, "some/path");
	ਮੁਕਤ(user); ਮੁਕਤ(host); ਮੁਕਤ(ਰਸਤਾ);
	TEST_ਪੂਰਾ();
}
