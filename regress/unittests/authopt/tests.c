/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshkey *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	r = sshkey_load_public(test_data_file(name), &ret, ರಿಕ್ತ);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshauthopt *
default_authkey_opts(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshauthopt *
default_authkey_restrict_opts(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ret->permit_port_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ವರ್ಣ **
commasplit(ಧ್ರುವ ವರ್ಣ *s, size_t *np)
{
	ವರ್ಣ *ocp, *cp, *cp2, **ret = ರಿಕ್ತ;
	size_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, ರಿಕ್ತ);
	ಪ್ರತಿ (n = 0; (cp2 = strsep(&cp, ",")) != ರಿಕ್ತ;) {
		ret = recallocarray(ret, n, n + 1, ಪರಿಮಾಣ(*ret));
		ASSERT_PTR_NE(ret, ರಿಕ್ತ);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, ರಿಕ್ತ);
		ret[n++] = cp2;
	}
	ಮುಕ್ತ(ocp);
	*np = n;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
compare_opts(ಧ್ರುವ ಸಂರಚನಾ sshauthopt *opts,
    ಧ್ರುವ ಸಂರಚನಾ sshauthopt *expected)
{
	size_t i;

	ASSERT_PTR_NE(opts, ರಿಕ್ತ);
	ASSERT_PTR_NE(expected, ರಿಕ್ತ);
	ASSERT_PTR_NE(expected, opts); /* bozo :) */

#define FLAG_EQ(x) ASSERT_INT_EQ(opts->x, expected->x)
	FLAG_EQ(permit_port_forwarding_flag);
	FLAG_EQ(permit_agent_forwarding_flag);
	FLAG_EQ(permit_x11_forwarding_flag);
	FLAG_EQ(permit_pty_flag);
	FLAG_EQ(permit_user_rc);
	FLAG_EQ(restricted);
	FLAG_EQ(cert_authority);
#undef FLAG_EQ

#define STR_EQ(x) \
	ಕುರು { \
		ಯದಿ (expected->x == ರಿಕ್ತ) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		ಅನ್ಯಥಾ \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} ಯಾವತ್ (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_ಕೀಲಿಗಳು);
#undef STR_EQ

#define ARRAY_EQ(nx, x) \
	ಕುರು { \
		ASSERT_SIZE_T_EQ(opts->nx, expected->nx); \
		ಯದಿ (expected->nx == 0) \
			ಭಙ್ಗ; \
		ಪ್ರತಿ (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} ಯಾವತ್ (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#undef ARRAY_EQ
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_authkeys_parse(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshauthopt *opts, *expected;
	ಧ್ರುವ ವರ್ಣ *errstr;

#define FAIL_TEST(label, keywords) \
	ಕುರು { \
		TEST_START("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, ರಿಕ್ತ); \
		ASSERT_PTR_NE(errstr, ರಿಕ್ತ); \
		sshauthopt_free(opts); \
		TEST_DONE(); \
	} ಯಾವತ್ (0) 
#define CHECK_SUCCESS_AND_CLEANUP() \
	ಕುರು { \
		ಯದಿ (errstr != ರಿಕ್ತ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} ಯಾವತ್ (0)

	/* Basic tests */
	TEST_START("sshauthopt_parse empty");
	expected = default_authkey_opts();
	opts = sshauthopt_parse("", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_parse trailing whitespace");
	expected = default_authkey_opts();
	opts = sshauthopt_parse(" ", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_parse restrict");
	expected = default_authkey_restrict_opts();
	opts = sshauthopt_parse("restrict", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	/* Invalid syntax */
	FAIL_TEST("trailing comma", "restrict,");
	FAIL_TEST("bare comma", ",");
	FAIL_TEST("unknown option", "BLAH");
	FAIL_TEST("unknown option with trailing comma", "BLAH,");
	FAIL_TEST("unknown option with trailing whitespace", "BLAH ");

	/* force_tun_device */
	TEST_START("sshauthopt_parse tunnel explicit");
	expected = default_authkey_opts();
	expected->force_tun_device = 1;
	opts = sshauthopt_parse("tunnel=\"1\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_parse tunnel any");
	expected = default_authkey_opts();
	expected->force_tun_device = SSH_TUNID_ANY;
	opts = sshauthopt_parse("tunnel=\"any\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	FAIL_TEST("tunnel", "tunnel=\"blah\"");

	/* Flag options */
#define FLAG_TEST(keyword, var, val) \
	ಕುರು { \
		TEST_START("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse(keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse("restrict,"keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)
	/* Positive flags */
	FLAG_TEST("cert-authority", cert_authority, 1);
	FLAG_TEST("port-forwarding", permit_port_forwarding_flag, 1);
	FLAG_TEST("agent-forwarding", permit_agent_forwarding_flag, 1);
	FLAG_TEST("x11-forwarding", permit_x11_forwarding_flag, 1);
	FLAG_TEST("pty", permit_pty_flag, 1);
	FLAG_TEST("user-rc", permit_user_rc, 1);
	/* Negative flags */
	FLAG_TEST("no-port-forwarding", permit_port_forwarding_flag, 0);
	FLAG_TEST("no-agent-forwarding", permit_agent_forwarding_flag, 0);
	FLAG_TEST("no-x11-forwarding", permit_x11_forwarding_flag, 0);
	FLAG_TEST("no-pty", permit_pty_flag, 0);
	FLAG_TEST("no-user-rc", permit_user_rc, 0);
#undef FLAG_TEST
	FAIL_TEST("no-cert-authority", "no-cert-authority");

	/* String options */
#define STRING_TEST(keyword, var, val) \
	ಕುರು { \
		TEST_START("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ರಿಕ್ತ); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ರಿಕ್ತ); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_ಕೀಲಿಗಳು, "127.0.0.0/8");
#undef STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#define ARRAY_TEST(label, keywords, var, nvar, val) \
	ಕುರು { \
		TEST_START("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ರಿಕ್ತ); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ರಿಕ್ತ); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"bar=2\"",
	    env, nenv, "foo=1,bar=2");
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"foo=2\"",
	    env, nenv, "foo=1");
	ARRAY_TEST("permitopen", "permitopen=\"foo:123\",permitopen=\"bar:*\"",
	    permitopen, npermitopen, "foo:123,bar:*");
#undef ARRAY_TEST
	FAIL_TEST("environment", "environment=\",=bah\"");
	FAIL_TEST("permitopen port", "foo:bar");
	FAIL_TEST("permitopen missing port", "foo:");
	FAIL_TEST("permitopen missing port specification", "foo");
	FAIL_TEST("permitopen invalid host", "[:");

#undef CHECK_SUCCESS_AND_CLEANUP
#undef FAIL_TEST
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_cert_parse(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshkey *cert;
	ಸಂರಚನಾ sshauthopt *opts, *expected;

#define CHECK_SUCCESS_AND_CLEANUP() \
	ಕುರು { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} ಯಾವತ್ (0)
#define FLAG_TEST(keybase, var) \
	ಕುರು { \
		TEST_START("sshauthopt_from_cert no_" keybase); \
		cert = load_ಕೀಲಿ("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
		TEST_START("sshauthopt_from_cert only_" keybase); \
		cert = load_ಕೀಲಿ("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, ರಿಕ್ತ); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_port_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#undef FLAG_TEST

	TEST_START("sshauthopt_from_cert all permitted");
	cert = load_ಕೀಲಿ("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert nothing permitted");
	cert = load_ಕೀಲಿ("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, ರಿಕ್ತ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert force-command");
	cert = load_ಕೀಲಿ("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ರಿಕ್ತ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert source-address");
	cert = load_ಕೀಲಿ("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ರಿಕ್ತ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();
#undef CHECK_SUCCESS_AND_CLEANUP

#define FAIL_TEST(keybase) \
	ಕುರು { \
		TEST_START("sshauthopt_from_cert " keybase); \
		cert = load_ಕೀಲಿ(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, ರಿಕ್ತ); \
		sshkey_free(cert); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#undef FAIL_TEST
}

ಸ್ಥಿರ ಶೂನ್ಯ
test_merge(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshkey *cert;
	ಸಂರಚನಾ sshauthopt *ಕೀಲಿ_opts, *cert_opts, *merge_opts, *expected;
	ಧ್ರುವ ವರ್ಣ *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#define PREPARE(label, keyname, keywords) \
	ಕುರು { \
		expected = ರಿಕ್ತ; \
		TEST_START("sshauthopt_merge " label); \
		cert = load_ಕೀಲಿ(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, ರಿಕ್ತ); \
		ಕೀಲಿ_opts = sshauthopt_parse(keywords, &errstr); \
		ಯದಿ (errstr != ರಿಕ್ತ) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(ಕೀಲಿ_opts, ರಿಕ್ತ); \
		merge_opts = sshauthopt_merge(ಕೀಲಿ_opts, \
		    cert_opts, &errstr); \
	} ಯಾವತ್ (0)

	/* Cleanup stuff allocated by PREPARE() */
#define CLEANUP() \
	ಕುರು { \
		sshauthopt_free(expected); \
		sshauthopt_free(merge_opts); \
		sshauthopt_free(ಕೀಲಿ_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} ಯಾವತ್ (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#define CHECK_SUCCESS_AND_CLEANUP() \
	ಕುರು { \
		ಯದಿ (errstr != ರಿಕ್ತ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(merge_opts, expected); \
		CLEANUP(); \
	} ಯಾವತ್ (0)

	/* Check a single case of merging of flag options */
#define FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	ಕುರು { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, ರಿಕ್ತ); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} ಯಾವತ್ (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#define FLAG_TEST(keybase, keyword, var) \
	ಕುರು { \
		FLAG_CASE(keybase, "keys:default,yes cert:default,no", \
		    "no_" keybase, keyword, 0, 0, var, 0); \
		FLAG_CASE(keybase,"keys:-*,yes cert:default,no", \
		    "no_" keybase, "restrict," keyword, 1, 1, var, 0); \
		FLAG_CASE(keybase, "keys:default,no cert:default,no", \
		    "no_" keybase, "no-" keyword, 0, 0, var, 0); \
		FLAG_CASE(keybase, "keys:-*,no cert:default,no", \
		    "no_" keybase, "restrict,no-" keyword, 1, 1, var, 0); \
		\
		FLAG_CASE(keybase, "keys:default,yes cert:-*,yes", \
		    "only_" keybase, keyword, 1, 0, var, 1); \
		FLAG_CASE(keybase,"keys:-*,yes cert:-*,yes", \
		    "only_" keybase, "restrict," keyword, 1, 1, var, 1); \
		FLAG_CASE(keybase, "keys:default,no cert:-*,yes", \
		    "only_" keybase, "no-" keyword, 1, 0, var, 0); \
		FLAG_CASE(keybase, "keys:-*,no cert:-*,yes", \
		    "only_" keybase, "restrict,no-" keyword, 1, 1, var, 0); \
		\
		FLAG_CASE(keybase, "keys:default,yes cert:-*", \
		    "no_permit", keyword, 1, 0, var, 0); \
		FLAG_CASE(keybase,"keys:-*,yes cert:-*", \
		    "no_permit", "restrict," keyword, 1, 1, var, 0); \
		FLAG_CASE(keybase, "keys:default,no cert:-*", \
		    "no_permit", "no-" keyword, 1, 0, var, 0); \
		FLAG_CASE(keybase, "keys:-*,no cert:-*", \
		    "no_permit", "restrict,no-" keyword, 1, 1, var, 0); \
		\
		FLAG_CASE(keybase, "keys:default,yes cert:*", \
		    "all_permit", keyword, 0, 0, var, 1); \
		FLAG_CASE(keybase,"keys:-*,yes cert:*", \
		    "all_permit", "restrict," keyword, 1, 1, var, 1); \
		FLAG_CASE(keybase, "keys:default,no cert:*", \
		    "all_permit", "no-" keyword, 0, 0, var, 0); \
		FLAG_CASE(keybase, "keys:-*,no cert:*", \
		    "all_permit", "restrict,no-" keyword, 1, 1, var, 0); \
		\
	} ಯಾವತ್ (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_port_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#undef FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ರಿಕ್ತ);
	expected->required_from_host_ಕೀಲಿಗಳು = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ಕೀಲಿಗಳು, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_ಕೀಲಿಗಳು = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ಕೀಲಿಗಳು, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ರಿಕ್ತ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(merge_opts, ರಿಕ್ತ);
	CLEANUP();
	TEST_DONE();

	PREPARE("tunnel", "all_permit", "tunnel=\"6\"");
	expected = default_authkey_opts();
	expected->force_tun_device = 6;
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("permitopen", "all_permit",
	    "permitopen=\"127.0.0.1:*\",permitopen=\"127.0.0.1:123\"");
	expected = default_authkey_opts();
	expected->permitopen = commasplit("127.0.0.1:*,127.0.0.1:123",
	    &expected->npermitopen);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("environment", "all_permit",
	    "environment=\"foo=a\",environment=\"bar=b\"");
	expected = default_authkey_opts();
	expected->env = commasplit("foo=a,bar=b", &expected->nenv);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	ಬಾಹ್ಯ ವರ್ಣ *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_merge();
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	printf("no benchmarks\n");
}
