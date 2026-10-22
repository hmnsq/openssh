/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshkey *ret;
	ਪੂਰਨ r;

	r = sshkey_ਲੱਦੋ_ਜਨਤਕ(test_ਅੰਕੜੇ_file(name), &ret, ਨਿਰਾ);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਬਣਤਰ sshauthopt *
default_authkey_opts(ਖਾਲੀ)
{
	ਬਣਤਰ sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ret->permit_ਪੋਰਟ_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਬਣਤਰ sshauthopt *
default_authkey_restrict_opts(ਖਾਲੀ)
{
	ਬਣਤਰ sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ret->permit_ਪੋਰਟ_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅੱਖਰ **
commasplit(ਅਚਲ ਅੱਖਰ *s, ਮਾਪ_t *np)
{
	ਅੱਖਰ *ocp, *cp, *cp2, **ret = ਨਿਰਾ;
	ਮਾਪ_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, ਨਿਰਾ);
	ਲਈ (n = 0; (cp2 = strsep(&cp, ",")) != ਨਿਰਾ;) {
		ret = recallocarray(ret, n, n + 1, ਆਕਾਰ(*ret));
		ASSERT_PTR_NE(ret, ਨਿਰਾ);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, ਨਿਰਾ);
		ret[n++] = cp2;
	}
	ਮੁਕਤ(ocp);
	*np = n;
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
compare_opts(ਅਚਲ ਬਣਤਰ sshauthopt *opts,
    ਅਚਲ ਬਣਤਰ sshauthopt *expected)
{
	ਮਾਪ_t i;

	ASSERT_PTR_NE(opts, ਨਿਰਾ);
	ASSERT_PTR_NE(expected, ਨਿਰਾ);
	ASSERT_PTR_NE(expected, opts); /* bozo :) */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_EQ(x) ASSERT_INT_EQ(opts->x, expected->x)
	FLAG_EQ(permit_ਪੋਰਟ_forwarding_flag);
	FLAG_EQ(permit_agent_forwarding_flag);
	FLAG_EQ(permit_x11_forwarding_flag);
	FLAG_EQ(permit_pty_flag);
	FLAG_EQ(permit_user_rc);
	FLAG_EQ(restricted);
	FLAG_EQ(cert_authority);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FLAG_EQ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STR_EQ(x) \
	ਕਰੋ { \
		ਜੇ (expected->x == ਨਿਰਾ) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		ਨਹੀਂਤਾਂ \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} ਜਦੋਂ (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_ਕੁੰਜੀਆਂ);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ STR_EQ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ARRAY_EQ(nx, x) \
	ਕਰੋ { \
		ASSERT_ਮਾਪ_T_EQ(opts->nx, expected->nx); \
		ਜੇ (expected->nx == 0) \
			ਰੋਕੋ; \
		ਲਈ (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} ਜਦੋਂ (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ARRAY_EQ
}

ਸਥਿਰ ਖਾਲੀ
test_authkeys_parse(ਖਾਲੀ)
{
	ਬਣਤਰ sshauthopt *opts, *expected;
	ਅਚਲ ਅੱਖਰ *errstr;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FAIL_TEST(label, keywords) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, ਨਿਰਾ); \
		ASSERT_PTR_NE(errstr, ਨਿਰਾ); \
		sshauthopt_free(opts); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0) 
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHECK_SUCCESS_AND_CLEANUP() \
	ਕਰੋ { \
		ਜੇ (errstr != ਨਿਰਾ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} ਜਦੋਂ (0)

	/* Basic tests */
	TEST_ਸ਼ੁਰੂ("sshauthopt_parse empty");
	expected = default_authkey_opts();
	opts = sshauthopt_parse("", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_parse trailing whitespace");
	expected = default_authkey_opts();
	opts = sshauthopt_parse(" ", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_parse restrict");
	expected = default_authkey_restrict_opts();
	opts = sshauthopt_parse("restrict", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	/* Invalid syntax */
	FAIL_TEST("trailing comma", "restrict,");
	FAIL_TEST("bare comma", ",");
	FAIL_TEST("unknown option", "BLAH");
	FAIL_TEST("unknown option with trailing comma", "BLAH,");
	FAIL_TEST("unknown option with trailing whitespace", "BLAH ");

	/* force_tun_device */
	TEST_ਸ਼ੁਰੂ("sshauthopt_parse tunnel explicit");
	expected = default_authkey_opts();
	expected->force_tun_device = 1;
	opts = sshauthopt_parse("tunnel=\"1\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_parse tunnel any");
	expected = default_authkey_opts();
	expected->force_tun_device = SSH_TUNID_ANY;
	opts = sshauthopt_parse("tunnel=\"any\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	FAIL_TEST("tunnel", "tunnel=\"blah\"");

	/* Flag options */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_TEST(keyword, var, val) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse(keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse("restrict,"keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)
	/* Positive flags */
	FLAG_TEST("cert-authority", cert_authority, 1);
	FLAG_TEST("port-forwarding", permit_ਪੋਰਟ_forwarding_flag, 1);
	FLAG_TEST("agent-forwarding", permit_agent_forwarding_flag, 1);
	FLAG_TEST("x11-forwarding", permit_x11_forwarding_flag, 1);
	FLAG_TEST("pty", permit_pty_flag, 1);
	FLAG_TEST("user-rc", permit_user_rc, 1);
	/* Negative flags */
	FLAG_TEST("no-port-forwarding", permit_ਪੋਰਟ_forwarding_flag, 0);
	FLAG_TEST("no-agent-forwarding", permit_agent_forwarding_flag, 0);
	FLAG_TEST("no-x11-forwarding", permit_x11_forwarding_flag, 0);
	FLAG_TEST("no-pty", permit_pty_flag, 0);
	FLAG_TEST("no-user-rc", permit_user_rc, 0);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FLAG_TEST
	FAIL_TEST("no-cert-authority", "no-cert-authority");

	/* String options */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ STRING_TEST(keyword, var, val) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ਨਿਰਾ); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ਨਿਰਾ); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_ਕੁੰਜੀਆਂ, "127.0.0.0/8");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ARRAY_TEST(label, keywords, var, nvar, val) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ਨਿਰਾ); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ਨਿਰਾ); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"bar=2\"",
	    env, nenv, "foo=1,bar=2");
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"foo=2\"",
	    env, nenv, "foo=1");
	ARRAY_TEST("permitopen", "permitopen=\"foo:123\",permitopen=\"bar:*\"",
	    permitopen, npermitopen, "foo:123,bar:*");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ARRAY_TEST
	FAIL_TEST("environment", "environment=\",=bah\"");
	FAIL_TEST("permitopen port", "foo:bar");
	FAIL_TEST("permitopen missing port", "foo:");
	FAIL_TEST("permitopen missing port specification", "foo");
	FAIL_TEST("permitopen invalid host", "[:");

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CHECK_SUCCESS_AND_CLEANUP
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FAIL_TEST
}

ਸਥਿਰ ਖਾਲੀ
test_cert_parse(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *cert;
	ਬਣਤਰ sshauthopt *opts, *expected;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHECK_SUCCESS_AND_CLEANUP() \
	ਕਰੋ { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} ਜਦੋਂ (0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_TEST(keybase, var) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert no_" keybase); \
		cert = ਲੱਦੋ_ਕੁੰਜੀ("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
		TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert only_" keybase); \
		cert = ਲੱਦੋ_ਕੁੰਜੀ("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, ਨਿਰਾ); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_ਪੋਰਟ_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FLAG_TEST

	TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert all permitted");
	cert = ਲੱਦੋ_ਕੁੰਜੀ("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert nothing permitted");
	cert = ਲੱਦੋ_ਕੁੰਜੀ("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, ਨਿਰਾ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert force-command");
	cert = ਲੱਦੋ_ਕੁੰਜੀ("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ਨਿਰਾ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert source-address");
	cert = ਲੱਦੋ_ਕੁੰਜੀ("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ਨਿਰਾ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CHECK_SUCCESS_AND_CLEANUP

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FAIL_TEST(keybase) \
	ਕਰੋ { \
		TEST_ਸ਼ੁਰੂ("sshauthopt_from_cert " keybase); \
		cert = ਲੱਦੋ_ਕੁੰਜੀ(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, ਨਿਰਾ); \
		sshkey_free(cert); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FAIL_TEST
}

ਸਥਿਰ ਖਾਲੀ
test_ਮਿਲਾਓ(ਖਾਲੀ)
{
	ਬਣਤਰ sshkey *cert;
	ਬਣਤਰ sshauthopt *ਕੁੰਜੀ_opts, *cert_opts, *ਮਿਲਾਓ_opts, *expected;
	ਅਚਲ ਅੱਖਰ *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PREPARE(label, keyname, keywords) \
	ਕਰੋ { \
		expected = ਨਿਰਾ; \
		TEST_ਸ਼ੁਰੂ("sshauthopt_merge " label); \
		cert = ਲੱਦੋ_ਕੁੰਜੀ(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, ਨਿਰਾ); \
		ਕੁੰਜੀ_opts = sshauthopt_parse(keywords, &errstr); \
		ਜੇ (errstr != ਨਿਰਾ) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(ਕੁੰਜੀ_opts, ਨਿਰਾ); \
		ਮਿਲਾਓ_opts = sshauthopt_ਮਿਲਾਓ(ਕੁੰਜੀ_opts, \
		    cert_opts, &errstr); \
	} ਜਦੋਂ (0)

	/* Cleanup stuff allocated by PREPARE() */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEANUP() \
	ਕਰੋ { \
		sshauthopt_free(expected); \
		sshauthopt_free(ਮਿਲਾਓ_opts); \
		sshauthopt_free(ਕੁੰਜੀ_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} ਜਦੋਂ (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHECK_SUCCESS_AND_CLEANUP() \
	ਕਰੋ { \
		ਜੇ (errstr != ਨਿਰਾ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(ਮਿਲਾਓ_opts, expected); \
		CLEANUP(); \
	} ਜਦੋਂ (0)

	/* Check a single case of merging of flag options */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	ਕਰੋ { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, ਨਿਰਾ); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_ਪੂਰਾ(); \
	} ਜਦੋਂ (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FLAG_TEST(keybase, keyword, var) \
	ਕਰੋ { \
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
	} ਜਦੋਂ (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_ਪੋਰਟ_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ਨਿਰਾ);
	expected->required_from_host_ਕੁੰਜੀਆਂ = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ਕੁੰਜੀਆਂ, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_ਕੁੰਜੀਆਂ = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ਕੁੰਜੀਆਂ, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ਨਿਰਾ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(ਮਿਲਾਓ_opts, ਨਿਰਾ);
	CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("tunnel", "all_permit", "tunnel=\"6\"");
	expected = default_authkey_opts();
	expected->force_tun_device = 6;
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("permitopen", "all_permit",
	    "permitopen=\"127.0.0.1:*\",permitopen=\"127.0.0.1:123\"");
	expected = default_authkey_opts();
	expected->permitopen = commasplit("127.0.0.1:*,127.0.0.1:123",
	    &expected->npermitopen);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();

	PREPARE("environment", "all_permit",
	    "environment=\"foo=a\",environment=\"bar=b\"");
	expected = default_authkey_opts();
	expected->env = commasplit("foo=a,bar=b", &expected->nenv);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_ਪੂਰਾ();
}

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	ਬਾਹਰੀ ਅੱਖਰ *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_ਮਿਲਾਓ();
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
