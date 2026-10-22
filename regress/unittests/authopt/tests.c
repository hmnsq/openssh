/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "sshkey.h"
#ضمن "authfile.h"
#ضمن "auth-options.h"
#ضمن "misc.h"
#ضمن "log.h"

ساكن بنية sshkey *
ڀريو_ڪنجي(ثابت حرف *name)
{
	بنية sshkey *ret;
	صحيح r;

	r = sshkey_ڀريو_عوامي(test_معلومات_file(name), &ret, عدم);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

ساكن بنية sshauthopt *
default_authkey_opts(فراغ)
{
	بنية sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, عدم);
	ret->permit_پورٽ_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	أرجع ret;
}

ساكن بنية sshauthopt *
default_authkey_restrict_opts(فراغ)
{
	بنية sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, عدم);
	ret->permit_پورٽ_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	أرجع ret;
}

ساكن حرف **
commasplit(ثابت حرف *s, سائيز_t *np)
{
	حرف *ocp, *cp, *cp2, **ret = عدم;
	سائيز_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, عدم);
	لكل (n = 0; (cp2 = strsep(&cp, ",")) != عدم;) {
		ret = recallocarray(ret, n, n + 1, حجم(*ret));
		ASSERT_PTR_NE(ret, عدم);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, عدم);
		ret[n++] = cp2;
	}
	حرر(ocp);
	*np = n;
	أرجع ret;
}

ساكن فراغ
compare_opts(ثابت بنية sshauthopt *opts,
    ثابت بنية sshauthopt *expected)
{
	سائيز_t i;

	ASSERT_PTR_NE(opts, عدم);
	ASSERT_PTR_NE(expected, عدم);
	ASSERT_PTR_NE(expected, opts); /* bozo :) */

#وصف_ڪريو FLAG_EQ(x) ASSERT_INT_EQ(opts->x, expected->x)
	FLAG_EQ(permit_پورٽ_forwarding_flag);
	FLAG_EQ(permit_agent_forwarding_flag);
	FLAG_EQ(permit_x11_forwarding_flag);
	FLAG_EQ(permit_pty_flag);
	FLAG_EQ(permit_user_rc);
	FLAG_EQ(restricted);
	FLAG_EQ(cert_authority);
#وصف_رد FLAG_EQ

#وصف_ڪريو STR_EQ(x) \
	افعل { \
		إذا (expected->x == عدم) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		وإلا \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} طالما (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_ڪنجيون);
#وصف_رد STR_EQ

#وصف_ڪريو ARRAY_EQ(nx, x) \
	افعل { \
		ASSERT_سائيز_T_EQ(opts->nx, expected->nx); \
		إذا (expected->nx == 0) \
			اكسر; \
		لكل (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} طالما (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#وصف_رد ARRAY_EQ
}

ساكن فراغ
test_authkeys_parse(فراغ)
{
	بنية sshauthopt *opts, *expected;
	ثابت حرف *errstr;

#وصف_ڪريو FAIL_TEST(label, keywords) \
	افعل { \
		TEST_شروعات("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, عدم); \
		ASSERT_PTR_NE(errstr, عدم); \
		sshauthopt_free(opts); \
		TEST_پورو(); \
	} طالما (0) 
#وصف_ڪريو CHECK_SUCCESS_AND_CLEANUP() \
	افعل { \
		إذا (errstr != عدم) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} طالما (0)

	/* Basic tests */
	TEST_شروعات("sshauthopt_parse empty");
	expected = default_authkey_opts();
	opts = sshauthopt_parse("", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_parse trailing whitespace");
	expected = default_authkey_opts();
	opts = sshauthopt_parse(" ", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_parse restrict");
	expected = default_authkey_restrict_opts();
	opts = sshauthopt_parse("restrict", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	/* Invalid syntax */
	FAIL_TEST("trailing comma", "restrict,");
	FAIL_TEST("bare comma", ",");
	FAIL_TEST("unknown option", "BLAH");
	FAIL_TEST("unknown option with trailing comma", "BLAH,");
	FAIL_TEST("unknown option with trailing whitespace", "BLAH ");

	/* force_tun_device */
	TEST_شروعات("sshauthopt_parse tunnel explicit");
	expected = default_authkey_opts();
	expected->force_tun_device = 1;
	opts = sshauthopt_parse("tunnel=\"1\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_parse tunnel any");
	expected = default_authkey_opts();
	expected->force_tun_device = SSH_TUNID_ANY;
	opts = sshauthopt_parse("tunnel=\"any\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	FAIL_TEST("tunnel", "tunnel=\"blah\"");

	/* Flag options */
#وصف_ڪريو FLAG_TEST(keyword, var, val) \
	افعل { \
		TEST_شروعات("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse(keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse("restrict,"keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
	} طالما (0)
	/* Positive flags */
	FLAG_TEST("cert-authority", cert_authority, 1);
	FLAG_TEST("port-forwarding", permit_پورٽ_forwarding_flag, 1);
	FLAG_TEST("agent-forwarding", permit_agent_forwarding_flag, 1);
	FLAG_TEST("x11-forwarding", permit_x11_forwarding_flag, 1);
	FLAG_TEST("pty", permit_pty_flag, 1);
	FLAG_TEST("user-rc", permit_user_rc, 1);
	/* Negative flags */
	FLAG_TEST("no-port-forwarding", permit_پورٽ_forwarding_flag, 0);
	FLAG_TEST("no-agent-forwarding", permit_agent_forwarding_flag, 0);
	FLAG_TEST("no-x11-forwarding", permit_x11_forwarding_flag, 0);
	FLAG_TEST("no-pty", permit_pty_flag, 0);
	FLAG_TEST("no-user-rc", permit_user_rc, 0);
#وصف_رد FLAG_TEST
	FAIL_TEST("no-cert-authority", "no-cert-authority");

	/* String options */
#وصف_ڪريو STRING_TEST(keyword, var, val) \
	افعل { \
		TEST_شروعات("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, عدم); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, عدم); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
	} طالما (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_ڪنجيون, "127.0.0.0/8");
#وصف_رد STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#وصف_ڪريو ARRAY_TEST(label, keywords, var, nvar, val) \
	افعل { \
		TEST_شروعات("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, عدم); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, عدم); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
	} طالما (0)
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"bar=2\"",
	    env, nenv, "foo=1,bar=2");
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"foo=2\"",
	    env, nenv, "foo=1");
	ARRAY_TEST("permitopen", "permitopen=\"foo:123\",permitopen=\"bar:*\"",
	    permitopen, npermitopen, "foo:123,bar:*");
#وصف_رد ARRAY_TEST
	FAIL_TEST("environment", "environment=\",=bah\"");
	FAIL_TEST("permitopen port", "foo:bar");
	FAIL_TEST("permitopen missing port", "foo:");
	FAIL_TEST("permitopen missing port specification", "foo");
	FAIL_TEST("permitopen invalid host", "[:");

#وصف_رد CHECK_SUCCESS_AND_CLEANUP
#وصف_رد FAIL_TEST
}

ساكن فراغ
test_cert_parse(فراغ)
{
	بنية sshkey *cert;
	بنية sshauthopt *opts, *expected;

#وصف_ڪريو CHECK_SUCCESS_AND_CLEANUP() \
	افعل { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} طالما (0)
#وصف_ڪريو FLAG_TEST(keybase, var) \
	افعل { \
		TEST_شروعات("sshauthopt_from_cert no_" keybase); \
		cert = ڀريو_ڪنجي("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
		TEST_شروعات("sshauthopt_from_cert only_" keybase); \
		cert = ڀريو_ڪنجي("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, عدم); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
	} طالما (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_پورٽ_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#وصف_رد FLAG_TEST

	TEST_شروعات("sshauthopt_from_cert all permitted");
	cert = ڀريو_ڪنجي("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_from_cert nothing permitted");
	cert = ڀريو_ڪنجي("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, عدم);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_from_cert force-command");
	cert = ڀريو_ڪنجي("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, عدم);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	TEST_شروعات("sshauthopt_from_cert source-address");
	cert = ڀريو_ڪنجي("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, عدم);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();
#وصف_رد CHECK_SUCCESS_AND_CLEANUP

#وصف_ڪريو FAIL_TEST(keybase) \
	افعل { \
		TEST_شروعات("sshauthopt_from_cert " keybase); \
		cert = ڀريو_ڪنجي(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, عدم); \
		sshkey_free(cert); \
		TEST_پورو(); \
	} طالما (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#وصف_رد FAIL_TEST
}

ساكن فراغ
test_ملايو(فراغ)
{
	بنية sshkey *cert;
	بنية sshauthopt *ڪنجي_opts, *cert_opts, *ملايو_opts, *expected;
	ثابت حرف *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#وصف_ڪريو PREPARE(label, keyname, keywords) \
	افعل { \
		expected = عدم; \
		TEST_شروعات("sshauthopt_merge " label); \
		cert = ڀريو_ڪنجي(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, عدم); \
		ڪنجي_opts = sshauthopt_parse(keywords, &errstr); \
		إذا (errstr != عدم) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(ڪنجي_opts, عدم); \
		ملايو_opts = sshauthopt_ملايو(ڪنجي_opts, \
		    cert_opts, &errstr); \
	} طالما (0)

	/* Cleanup stuff allocated by PREPARE() */
#وصف_ڪريو CLEANUP() \
	افعل { \
		sshauthopt_free(expected); \
		sshauthopt_free(ملايو_opts); \
		sshauthopt_free(ڪنجي_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} طالما (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#وصف_ڪريو CHECK_SUCCESS_AND_CLEANUP() \
	افعل { \
		إذا (errstr != عدم) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(ملايو_opts, expected); \
		CLEANUP(); \
	} طالما (0)

	/* Check a single case of merging of flag options */
#وصف_ڪريو FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	افعل { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, عدم); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_پورو(); \
	} طالما (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#وصف_ڪريو FLAG_TEST(keybase, keyword, var) \
	افعل { \
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
	} طالما (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_پورٽ_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#وصف_رد FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, عدم);
	expected->required_from_host_ڪنجيون = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ڪنجيون, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_ڪنجيون = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ڪنجيون, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, عدم);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(ملايو_opts, عدم);
	CLEANUP();
	TEST_پورو();

	PREPARE("tunnel", "all_permit", "tunnel=\"6\"");
	expected = default_authkey_opts();
	expected->force_tun_device = 6;
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("permitopen", "all_permit",
	    "permitopen=\"127.0.0.1:*\",permitopen=\"127.0.0.1:123\"");
	expected = default_authkey_opts();
	expected->permitopen = commasplit("127.0.0.1:*,127.0.0.1:123",
	    &expected->npermitopen);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();

	PREPARE("environment", "all_permit",
	    "environment=\"foo=a\",environment=\"bar=b\"");
	expected = default_authkey_opts();
	expected->env = commasplit("foo=a,bar=b", &expected->nenv);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_پورو();
}

فراغ
tests(فراغ)
{
	خارجي حرف *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_ملايو();
}

فراغ
benchmarks(فراغ)
{
	لکو("no benchmarks\n");
}
