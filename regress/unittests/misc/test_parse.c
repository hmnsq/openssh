/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
 *
 * Placed in the public domain.
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

શૂન્ય test_parse(શૂન્ય);

શૂન્ય
test_parse(શૂન્ય)
{
	પૂર્ણાંક port;
	અક્ષર *user, *host, *path;

	TEST_START("misc_parse_user_host_path");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_user_host_path("someuser@some.host:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(path, "some/path");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv4_path");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_user_host_path("someuser@1.22.33.144:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_path");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, "some/path");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();

	TEST_START("misc_parse_user_[ipv4]_nopath");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[1.22.33.144]:",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(path, ".");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();

	TEST_START("misc_parse_user_ipv6_path");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_user_host_path("someuser@[::1]:some/path",
	    &user, &host, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(path, "some/path");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();

	TEST_START("misc_parse_uri");
	user = host = path = ખાલી;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &port, &path), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(port, 22);
	ASSERT_STRING_EQ(path, "some/path");
	મુક્ત(user); મુક્ત(host); મુક્ત(path);
	TEST_DONE();
}
