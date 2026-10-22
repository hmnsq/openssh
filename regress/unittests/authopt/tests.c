/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "sshkey.h"
#شامل "authfile.h"
#شامل "auth-options.h"
#شامل "misc.h"
#شامل "log.h"

ساکن ساخت sshkey *
بھرو_کلید(ثابت حرف *name)
{
	ساخت sshkey *ret;
	صحیح r;

	r = sshkey_بھرو_عوامی(test_ڈیٹا_file(name), &ret, تہی);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, تہی);
	واپس ret;
}

ساکن ساخت sshauthopt *
default_authkey_opts(خالی)
{
	ساخت sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, تہی);
	ret->permit_پورٹ_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	واپس ret;
}

ساکن ساخت sshauthopt *
default_authkey_restrict_opts(خالی)
{
	ساخت sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, تہی);
	ret->permit_پورٹ_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	واپس ret;
}

ساکن حرف **
commasplit(ثابت حرف *s, سائز_t *np)
{
	حرف *ocp, *cp, *cp2, **ret = تہی;
	سائز_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, تہی);
	برائے (n = 0; (cp2 = strsep(&cp, ",")) != تہی;) {
		ret = recallocarray(ret, n, n + 1, حجم(*ret));
		ASSERT_PTR_NE(ret, تہی);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, تہی);
		ret[n++] = cp2;
	}
	آزاد(ocp);
	*np = n;
	واپس ret;
}

ساکن خالی
compare_opts(ثابت ساخت sshauthopt *opts,
    ثابت ساخت sshauthopt *expected)
{
	سائز_t i;

	ASSERT_PTR_NE(opts, تہی);
	ASSERT_PTR_NE(expected, تہی);
	ASSERT_PTR_NE(expected, opts); /* bozo :) */

#تعریف_کرو FLAG_EQ(x) ASSERT_INT_EQ(opts->x, expected->x)
	FLAG_EQ(permit_پورٹ_forwarding_flag);
	FLAG_EQ(permit_agent_forwarding_flag);
	FLAG_EQ(permit_x11_forwarding_flag);
	FLAG_EQ(permit_pty_flag);
	FLAG_EQ(permit_user_rc);
	FLAG_EQ(restricted);
	FLAG_EQ(cert_authority);
#تعریف_منسوخ FLAG_EQ

#تعریف_کرو STR_EQ(x) \
	کرو { \
		اگر (expected->x == تہی) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		ورنہ \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} جب (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_کلیدیں);
#تعریف_منسوخ STR_EQ

#تعریف_کرو ARRAY_EQ(nx, x) \
	کرو { \
		ASSERT_سائز_T_EQ(opts->nx, expected->nx); \
		اگر (expected->nx == 0) \
			توڑو; \
		برائے (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} جب (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#تعریف_منسوخ ARRAY_EQ
}

ساکن خالی
test_authkeys_parse(خالی)
{
	ساخت sshauthopt *opts, *expected;
	ثابت حرف *errstr;

#تعریف_کرو FAIL_TEST(label, keywords) \
	کرو { \
		TEST_آغاز("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, تہی); \
		ASSERT_PTR_NE(errstr, تہی); \
		sshauthopt_free(opts); \
		TEST_مکمل(); \
	} جب (0) 
#تعریف_کرو CHECK_SUCCESS_AND_CLEANUP() \
	کرو { \
		اگر (errstr != تہی) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} جب (0)

	/* Basic tests */
	TEST_آغاز("sshauthopt_parse empty");
	expected = default_authkey_opts();
	opts = sshauthopt_parse("", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_parse trailing whitespace");
	expected = default_authkey_opts();
	opts = sshauthopt_parse(" ", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_parse restrict");
	expected = default_authkey_restrict_opts();
	opts = sshauthopt_parse("restrict", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	/* Invalid syntax */
	FAIL_TEST("trailing comma", "restrict,");
	FAIL_TEST("bare comma", ",");
	FAIL_TEST("unknown option", "BLAH");
	FAIL_TEST("unknown option with trailing comma", "BLAH,");
	FAIL_TEST("unknown option with trailing whitespace", "BLAH ");

	/* force_tun_device */
	TEST_آغاز("sshauthopt_parse tunnel explicit");
	expected = default_authkey_opts();
	expected->force_tun_device = 1;
	opts = sshauthopt_parse("tunnel=\"1\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_parse tunnel any");
	expected = default_authkey_opts();
	expected->force_tun_device = SSH_TUNID_ANY;
	opts = sshauthopt_parse("tunnel=\"any\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	FAIL_TEST("tunnel", "tunnel=\"blah\"");

	/* Flag options */
#تعریف_کرو FLAG_TEST(keyword, var, val) \
	کرو { \
		TEST_آغاز("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse(keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse("restrict,"keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
	} جب (0)
	/* Positive flags */
	FLAG_TEST("cert-authority", cert_authority, 1);
	FLAG_TEST("port-forwarding", permit_پورٹ_forwarding_flag, 1);
	FLAG_TEST("agent-forwarding", permit_agent_forwarding_flag, 1);
	FLAG_TEST("x11-forwarding", permit_x11_forwarding_flag, 1);
	FLAG_TEST("pty", permit_pty_flag, 1);
	FLAG_TEST("user-rc", permit_user_rc, 1);
	/* Negative flags */
	FLAG_TEST("no-port-forwarding", permit_پورٹ_forwarding_flag, 0);
	FLAG_TEST("no-agent-forwarding", permit_agent_forwarding_flag, 0);
	FLAG_TEST("no-x11-forwarding", permit_x11_forwarding_flag, 0);
	FLAG_TEST("no-pty", permit_pty_flag, 0);
	FLAG_TEST("no-user-rc", permit_user_rc, 0);
#تعریف_منسوخ FLAG_TEST
	FAIL_TEST("no-cert-authority", "no-cert-authority");

	/* String options */
#تعریف_کرو STRING_TEST(keyword, var, val) \
	کرو { \
		TEST_آغاز("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, تہی); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, تہی); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
	} جب (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_کلیدیں, "127.0.0.0/8");
#تعریف_منسوخ STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#تعریف_کرو ARRAY_TEST(label, keywords, var, nvar, val) \
	کرو { \
		TEST_آغاز("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, تہی); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, تہی); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
	} جب (0)
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"bar=2\"",
	    env, nenv, "foo=1,bar=2");
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"foo=2\"",
	    env, nenv, "foo=1");
	ARRAY_TEST("permitopen", "permitopen=\"foo:123\",permitopen=\"bar:*\"",
	    permitopen, npermitopen, "foo:123,bar:*");
#تعریف_منسوخ ARRAY_TEST
	FAIL_TEST("environment", "environment=\",=bah\"");
	FAIL_TEST("permitopen port", "foo:bar");
	FAIL_TEST("permitopen missing port", "foo:");
	FAIL_TEST("permitopen missing port specification", "foo");
	FAIL_TEST("permitopen invalid host", "[:");

#تعریف_منسوخ CHECK_SUCCESS_AND_CLEANUP
#تعریف_منسوخ FAIL_TEST
}

ساکن خالی
test_cert_parse(خالی)
{
	ساخت sshkey *cert;
	ساخت sshauthopt *opts, *expected;

#تعریف_کرو CHECK_SUCCESS_AND_CLEANUP() \
	کرو { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} جب (0)
#تعریف_کرو FLAG_TEST(keybase, var) \
	کرو { \
		TEST_آغاز("sshauthopt_from_cert no_" keybase); \
		cert = بھرو_کلید("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
		TEST_آغاز("sshauthopt_from_cert only_" keybase); \
		cert = بھرو_کلید("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, تہی); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
	} جب (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_پورٹ_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#تعریف_منسوخ FLAG_TEST

	TEST_آغاز("sshauthopt_from_cert all permitted");
	cert = بھرو_کلید("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_from_cert nothing permitted");
	cert = بھرو_کلید("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, تہی);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_from_cert force-command");
	cert = بھرو_کلید("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, تہی);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	TEST_آغاز("sshauthopt_from_cert source-address");
	cert = بھرو_کلید("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, تہی);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();
#تعریف_منسوخ CHECK_SUCCESS_AND_CLEANUP

#تعریف_کرو FAIL_TEST(keybase) \
	کرو { \
		TEST_آغاز("sshauthopt_from_cert " keybase); \
		cert = بھرو_کلید(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, تہی); \
		sshkey_free(cert); \
		TEST_مکمل(); \
	} جب (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#تعریف_منسوخ FAIL_TEST
}

ساکن خالی
test_ملاؤ(خالی)
{
	ساخت sshkey *cert;
	ساخت sshauthopt *کلید_opts, *cert_opts, *ملاؤ_opts, *expected;
	ثابت حرف *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#تعریف_کرو PREPARE(label, keyname, keywords) \
	کرو { \
		expected = تہی; \
		TEST_آغاز("sshauthopt_merge " label); \
		cert = بھرو_کلید(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, تہی); \
		کلید_opts = sshauthopt_parse(keywords, &errstr); \
		اگر (errstr != تہی) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(کلید_opts, تہی); \
		ملاؤ_opts = sshauthopt_ملاؤ(کلید_opts, \
		    cert_opts, &errstr); \
	} جب (0)

	/* Cleanup stuff allocated by PREPARE() */
#تعریف_کرو CLEANUP() \
	کرو { \
		sshauthopt_free(expected); \
		sshauthopt_free(ملاؤ_opts); \
		sshauthopt_free(کلید_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} جب (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#تعریف_کرو CHECK_SUCCESS_AND_CLEANUP() \
	کرو { \
		اگر (errstr != تہی) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(ملاؤ_opts, expected); \
		CLEANUP(); \
	} جب (0)

	/* Check a single case of merging of flag options */
#تعریف_کرو FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	کرو { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, تہی); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_مکمل(); \
	} جب (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#تعریف_کرو FLAG_TEST(keybase, keyword, var) \
	کرو { \
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
	} جب (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_پورٹ_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#تعریف_منسوخ FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, تہی);
	expected->required_from_host_کلیدیں = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_کلیدیں, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_کلیدیں = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_کلیدیں, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, تہی);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(ملاؤ_opts, تہی);
	CLEANUP();
	TEST_مکمل();

	PREPARE("tunnel", "all_permit", "tunnel=\"6\"");
	expected = default_authkey_opts();
	expected->force_tun_device = 6;
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("permitopen", "all_permit",
	    "permitopen=\"127.0.0.1:*\",permitopen=\"127.0.0.1:123\"");
	expected = default_authkey_opts();
	expected->permitopen = commasplit("127.0.0.1:*,127.0.0.1:123",
	    &expected->npermitopen);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();

	PREPARE("environment", "all_permit",
	    "environment=\"foo=a\",environment=\"bar=b\"");
	expected = default_authkey_opts();
	expected->env = commasplit("foo=a,bar=b", &expected->nenv);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_مکمل();
}

خالی
tests(خالی)
{
	خارجی حرف *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_ملاؤ();
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
