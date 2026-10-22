/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"

સ્થિર સંરચના sshkey *
load_ચાવી(અચલ અક્ષર *name)
{
	સંરચના sshkey *ret;
	પૂર્ણાંક r;

	r = sshkey_load_public(test_data_file(name), &ret, ખાલી);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, ખાલી);
	પાછા ret;
}

સ્થિર સંરચના sshauthopt *
default_authkey_opts(શૂન્ય)
{
	સંરચના sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ખાલી);
	ret->permit_port_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	પાછા ret;
}

સ્થિર સંરચના sshauthopt *
default_authkey_restrict_opts(શૂન્ય)
{
	સંરચના sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ખાલી);
	ret->permit_port_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	પાછા ret;
}

સ્થિર અક્ષર **
commasplit(અચલ અક્ષર *s, size_t *np)
{
	અક્ષર *ocp, *cp, *cp2, **ret = ખાલી;
	size_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, ખાલી);
	માટે (n = 0; (cp2 = strsep(&cp, ",")) != ખાલી;) {
		ret = recallocarray(ret, n, n + 1, કદ(*ret));
		ASSERT_PTR_NE(ret, ખાલી);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, ખાલી);
		ret[n++] = cp2;
	}
	મુક્ત(ocp);
	*np = n;
	પાછા ret;
}

સ્થિર શૂન્ય
compare_opts(અચલ સંરચના sshauthopt *opts,
    અચલ સંરચના sshauthopt *expected)
{
	size_t i;

	ASSERT_PTR_NE(opts, ખાલી);
	ASSERT_PTR_NE(expected, ખાલી);
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
	કરો { \
		જો (expected->x == ખાલી) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		નહીંતર \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} જ્યારે (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_ચાવીઓ);
#undef STR_EQ

#define ARRAY_EQ(nx, x) \
	કરો { \
		ASSERT_SIZE_T_EQ(opts->nx, expected->nx); \
		જો (expected->nx == 0) \
			તોડો; \
		માટે (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} જ્યારે (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#undef ARRAY_EQ
}

સ્થિર શૂન્ય
test_authkeys_parse(શૂન્ય)
{
	સંરચના sshauthopt *opts, *expected;
	અચલ અક્ષર *errstr;

#define FAIL_TEST(label, keywords) \
	કરો { \
		TEST_START("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, ખાલી); \
		ASSERT_PTR_NE(errstr, ખાલી); \
		sshauthopt_free(opts); \
		TEST_DONE(); \
	} જ્યારે (0) 
#define CHECK_SUCCESS_AND_CLEANUP() \
	કરો { \
		જો (errstr != ખાલી) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} જ્યારે (0)

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
	કરો { \
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
	} જ્યારે (0)
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
	કરો { \
		TEST_START("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ખાલી); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ખાલી); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} જ્યારે (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_ચાવીઓ, "127.0.0.0/8");
#undef STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#define ARRAY_TEST(label, keywords, var, nvar, val) \
	કરો { \
		TEST_START("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ખાલી); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ખાલી); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} જ્યારે (0)
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

સ્થિર શૂન્ય
test_cert_parse(શૂન્ય)
{
	સંરચના sshkey *cert;
	સંરચના sshauthopt *opts, *expected;

#define CHECK_SUCCESS_AND_CLEANUP() \
	કરો { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} જ્યારે (0)
#define FLAG_TEST(keybase, var) \
	કરો { \
		TEST_START("sshauthopt_from_cert no_" keybase); \
		cert = load_ચાવી("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
		TEST_START("sshauthopt_from_cert only_" keybase); \
		cert = load_ચાવી("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, ખાલી); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} જ્યારે (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_port_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#undef FLAG_TEST

	TEST_START("sshauthopt_from_cert all permitted");
	cert = load_ચાવી("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert nothing permitted");
	cert = load_ચાવી("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, ખાલી);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert force-command");
	cert = load_ચાવી("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ખાલી);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	TEST_START("sshauthopt_from_cert source-address");
	cert = load_ચાવી("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ખાલી);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();
#undef CHECK_SUCCESS_AND_CLEANUP

#define FAIL_TEST(keybase) \
	કરો { \
		TEST_START("sshauthopt_from_cert " keybase); \
		cert = load_ચાવી(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, ખાલી); \
		sshkey_free(cert); \
		TEST_DONE(); \
	} જ્યારે (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#undef FAIL_TEST
}

સ્થિર શૂન્ય
test_merge(શૂન્ય)
{
	સંરચના sshkey *cert;
	સંરચના sshauthopt *ચાવી_opts, *cert_opts, *merge_opts, *expected;
	અચલ અક્ષર *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#define PREPARE(label, keyname, keywords) \
	કરો { \
		expected = ખાલી; \
		TEST_START("sshauthopt_merge " label); \
		cert = load_ચાવી(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, ખાલી); \
		ચાવી_opts = sshauthopt_parse(keywords, &errstr); \
		જો (errstr != ખાલી) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(ચાવી_opts, ખાલી); \
		merge_opts = sshauthopt_merge(ચાવી_opts, \
		    cert_opts, &errstr); \
	} જ્યારે (0)

	/* Cleanup stuff allocated by PREPARE() */
#define CLEANUP() \
	કરો { \
		sshauthopt_free(expected); \
		sshauthopt_free(merge_opts); \
		sshauthopt_free(ચાવી_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} જ્યારે (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#define CHECK_SUCCESS_AND_CLEANUP() \
	કરો { \
		જો (errstr != ખાલી) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(merge_opts, expected); \
		CLEANUP(); \
	} જ્યારે (0)

	/* Check a single case of merging of flag options */
#define FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	કરો { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, ખાલી); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_DONE(); \
	} જ્યારે (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#define FLAG_TEST(keybase, keyword, var) \
	કરો { \
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
	} જ્યારે (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_port_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#undef FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ખાલી);
	expected->required_from_host_ચાવીઓ = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ચાવીઓ, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_ચાવીઓ = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_ચાવીઓ, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ખાલી);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_DONE();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(merge_opts, ખાલી);
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

શૂન્ય
tests(શૂન્ય)
{
	બાહ્ય અક્ષર *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_merge();
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
