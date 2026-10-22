/* 	$OpenBSD: test_parse.c,v 1.3 2025/06/12 10:09:39 dtucker Exp $ */
/*
 * Regress test for misc user/host/URI parsing functions.
 *
 * Placed in the public domain.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

శూన్య test_parse(శూన్య);

శూన్య
test_parse(శూన్య)
{
	పూర్ణాంకం పోర్టు;
	అక్షరం *user, *host, *మార్గం;

	TEST_ప్రారంభం("misc_parse_user_host_path");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_user_host_మార్గం("someuser@some.host:some/path",
	    &user, &host, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_STRING_EQ(మార్గం, "some/path");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();

	TEST_ప్రారంభం("misc_parse_user_ipv4_path");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_user_host_మార్గం("someuser@1.22.33.144:some/path",
	    &user, &host, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(మార్గం, "some/path");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();

	TEST_ప్రారంభం("misc_parse_user_[ipv4]_path");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_user_host_మార్గం("someuser@[1.22.33.144]:some/path",
	    &user, &host, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(మార్గం, "some/path");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();

	TEST_ప్రారంభం("misc_parse_user_[ipv4]_nopath");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_user_host_మార్గం("someuser@[1.22.33.144]:",
	    &user, &host, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "1.22.33.144");
	ASSERT_STRING_EQ(మార్గం, ".");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();

	TEST_ప్రారంభం("misc_parse_user_ipv6_path");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_user_host_మార్గం("someuser@[::1]:some/path",
	    &user, &host, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "::1");
	ASSERT_STRING_EQ(మార్గం, "some/path");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();

	TEST_ప్రారంభం("misc_parse_uri");
	user = host = మార్గం = ఖాళీ;
	ASSERT_INT_EQ(parse_uri("ssh", "ssh://someuser@some.host:22/some/path",
	    &user, &host, &పోర్టు, &మార్గం), 0);
	ASSERT_STRING_EQ(user, "someuser");
	ASSERT_STRING_EQ(host, "some.host");
	ASSERT_INT_EQ(పోర్టు, 22);
	ASSERT_STRING_EQ(మార్గం, "some/path");
	విడుదల(user); విడుదల(host); విడుదల(మార్గం);
	TEST_పూర్తి();
}
