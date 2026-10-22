/* 	$OpenBSD: tests.c,v 1.7 2026/09/16 04:56:12 djm Exp $ */

/*
 * Regress test for keys options functions.
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"

స్థిర నిర్మాణం sshkey *
ఎక్కించు_కీలకం(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshkey *ret;
	పూర్ణాంకం r;

	r = sshkey_ఎక్కించు_ప్రజా(test_దత్తాంశం_file(name), &ret, ఖాళీ);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(ret, ఖాళీ);
	తిరిగి ret;
}

స్థిర నిర్మాణం sshauthopt *
default_authkey_opts(శూన్య)
{
	నిర్మాణం sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ఖాళీ);
	ret->permit_పోర్టు_forwarding_flag = 1;
	ret->permit_agent_forwarding_flag = 1;
	ret->permit_x11_forwarding_flag = 1;
	ret->permit_pty_flag = 1;
	ret->permit_user_rc = 1;
	తిరిగి ret;
}

స్థిర నిర్మాణం sshauthopt *
default_authkey_restrict_opts(శూన్య)
{
	నిర్మాణం sshauthopt *ret = sshauthopt_new();

	ASSERT_PTR_NE(ret, ఖాళీ);
	ret->permit_పోర్టు_forwarding_flag = 0;
	ret->permit_agent_forwarding_flag = 0;
	ret->permit_x11_forwarding_flag = 0;
	ret->permit_pty_flag = 0;
	ret->permit_user_rc = 0;
	ret->restricted = 1;
	తిరిగి ret;
}

స్థిర అక్షరం **
commasplit(స్థిరరాశి అక్షరం *s, కొలత_t *np)
{
	అక్షరం *ocp, *cp, *cp2, **ret = ఖాళీ;
	కొలత_t n;

	ocp = cp = strdup(s);
	ASSERT_PTR_NE(cp, ఖాళీ);
	కొరకు (n = 0; (cp2 = strsep(&cp, ",")) != ఖాళీ;) {
		ret = recallocarray(ret, n, n + 1, పరిమాణం(*ret));
		ASSERT_PTR_NE(ret, ఖాళీ);
		cp2 = strdup(cp2);
		ASSERT_PTR_NE(cp2, ఖాళీ);
		ret[n++] = cp2;
	}
	విడుదల(ocp);
	*np = n;
	తిరిగి ret;
}

స్థిర శూన్య
compare_opts(స్థిరరాశి నిర్మాణం sshauthopt *opts,
    స్థిరరాశి నిర్మాణం sshauthopt *expected)
{
	కొలత_t i;

	ASSERT_PTR_NE(opts, ఖాళీ);
	ASSERT_PTR_NE(expected, ఖాళీ);
	ASSERT_PTR_NE(expected, opts); /* bozo :) */

#నిర్వచించు FLAG_EQ(x) ASSERT_INT_EQ(opts->x, expected->x)
	FLAG_EQ(permit_పోర్టు_forwarding_flag);
	FLAG_EQ(permit_agent_forwarding_flag);
	FLAG_EQ(permit_x11_forwarding_flag);
	FLAG_EQ(permit_pty_flag);
	FLAG_EQ(permit_user_rc);
	FLAG_EQ(restricted);
	FLAG_EQ(cert_authority);
#నిర్వచనం_రద్దు FLAG_EQ

#నిర్వచించు STR_EQ(x) \
	చేయి { \
		ఒకవేళ (expected->x == ఖాళీ) \
			ASSERT_PTR_EQ(opts->x, expected->x); \
		లేకపోతే \
			ASSERT_STRING_EQ(opts->x, expected->x); \
	} అయితే (0)
	STR_EQ(cert_principals);
	STR_EQ(force_command);
	STR_EQ(required_from_host_cert);
	STR_EQ(required_from_host_కీలకాలు);
#నిర్వచనం_రద్దు STR_EQ

#నిర్వచించు ARRAY_EQ(nx, x) \
	చేయి { \
		ASSERT_కొలత_T_EQ(opts->nx, expected->nx); \
		ఒకవేళ (expected->nx == 0) \
			ఆపు; \
		కొరకు (i = 0; i < expected->nx; i++) \
			ASSERT_STRING_EQ(opts->x[i], expected->x[i]); \
	} అయితే (0)
	ARRAY_EQ(nenv, env);
	ARRAY_EQ(npermitopen, permitopen);
#నిర్వచనం_రద్దు ARRAY_EQ
}

స్థిర శూన్య
test_authkeys_parse(శూన్య)
{
	నిర్మాణం sshauthopt *opts, *expected;
	స్థిరరాశి అక్షరం *errstr;

#నిర్వచించు FAIL_TEST(label, keywords) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_parse invalid " label); \
		opts = sshauthopt_parse(keywords, &errstr); \
		ASSERT_PTR_EQ(opts, ఖాళీ); \
		ASSERT_PTR_NE(errstr, ఖాళీ); \
		sshauthopt_free(opts); \
		TEST_పూర్తి(); \
	} అయితే (0) 
#నిర్వచించు CHECK_SUCCESS_AND_CLEANUP() \
	చేయి { \
		ఒకవేళ (errstr != ఖాళీ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
	} అయితే (0)

	/* Basic tests */
	TEST_ప్రారంభం("sshauthopt_parse empty");
	expected = default_authkey_opts();
	opts = sshauthopt_parse("", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_parse trailing whitespace");
	expected = default_authkey_opts();
	opts = sshauthopt_parse(" ", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_parse restrict");
	expected = default_authkey_restrict_opts();
	opts = sshauthopt_parse("restrict", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	/* Invalid syntax */
	FAIL_TEST("trailing comma", "restrict,");
	FAIL_TEST("bare comma", ",");
	FAIL_TEST("unknown option", "BLAH");
	FAIL_TEST("unknown option with trailing comma", "BLAH,");
	FAIL_TEST("unknown option with trailing whitespace", "BLAH ");

	/* force_tun_device */
	TEST_ప్రారంభం("sshauthopt_parse tunnel explicit");
	expected = default_authkey_opts();
	expected->force_tun_device = 1;
	opts = sshauthopt_parse("tunnel=\"1\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_parse tunnel any");
	expected = default_authkey_opts();
	expected->force_tun_device = SSH_TUNID_ANY;
	opts = sshauthopt_parse("tunnel=\"any\"", &errstr);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	FAIL_TEST("tunnel", "tunnel=\"blah\"");

	/* Flag options */
#నిర్వచించు FLAG_TEST(keyword, var, val) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse(keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = val; \
		opts = sshauthopt_parse("restrict,"keyword, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
	} అయితే (0)
	/* Positive flags */
	FLAG_TEST("cert-authority", cert_authority, 1);
	FLAG_TEST("port-forwarding", permit_పోర్టు_forwarding_flag, 1);
	FLAG_TEST("agent-forwarding", permit_agent_forwarding_flag, 1);
	FLAG_TEST("x11-forwarding", permit_x11_forwarding_flag, 1);
	FLAG_TEST("pty", permit_pty_flag, 1);
	FLAG_TEST("user-rc", permit_user_rc, 1);
	/* Negative flags */
	FLAG_TEST("no-port-forwarding", permit_పోర్టు_forwarding_flag, 0);
	FLAG_TEST("no-agent-forwarding", permit_agent_forwarding_flag, 0);
	FLAG_TEST("no-x11-forwarding", permit_x11_forwarding_flag, 0);
	FLAG_TEST("no-pty", permit_pty_flag, 0);
	FLAG_TEST("no-user-rc", permit_user_rc, 0);
#నిర్వచనం_రద్దు FLAG_TEST
	FAIL_TEST("no-cert-authority", "no-cert-authority");

	/* String options */
#నిర్వచించు STRING_TEST(keyword, var, val) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_parse " keyword); \
		expected = default_authkey_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ఖాళీ); \
		opts = sshauthopt_parse(keyword "=" #val, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = strdup(val); \
		ASSERT_PTR_NE(expected->var, ఖాళీ); \
		opts = sshauthopt_parse( \
		    "restrict," keyword "=" #val ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
	} అయితే (0)
	STRING_TEST("command", force_command, "/bin/true");
	STRING_TEST("principals", cert_principals, "gregor,josef,K");
	STRING_TEST("from", required_from_host_కీలకాలు, "127.0.0.0/8");
#నిర్వచనం_రద్దు STRING_TEST
	FAIL_TEST("unquoted command", "command=oops");
	FAIL_TEST("unquoted principals", "principals=estragon");
	FAIL_TEST("unquoted from", "from=127.0.0.1");

	/* String array option tests */
#నిర్వచించు ARRAY_TEST(label, keywords, var, nvar, val) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_parse " label); \
		expected = default_authkey_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ఖాళీ); \
		opts = sshauthopt_parse(keywords, &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		expected = default_authkey_restrict_opts(); \
		expected->var = commasplit(val, &expected->nvar); \
		ASSERT_PTR_NE(expected->var, ఖాళీ); \
		opts = sshauthopt_parse( \
		    "restrict," keywords ",restrict", &errstr); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
	} అయితే (0)
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"bar=2\"",
	    env, nenv, "foo=1,bar=2");
	ARRAY_TEST("environment", "environment=\"foo=1\",environment=\"foo=2\"",
	    env, nenv, "foo=1");
	ARRAY_TEST("permitopen", "permitopen=\"foo:123\",permitopen=\"bar:*\"",
	    permitopen, npermitopen, "foo:123,bar:*");
#నిర్వచనం_రద్దు ARRAY_TEST
	FAIL_TEST("environment", "environment=\",=bah\"");
	FAIL_TEST("permitopen port", "foo:bar");
	FAIL_TEST("permitopen missing port", "foo:");
	FAIL_TEST("permitopen missing port specification", "foo");
	FAIL_TEST("permitopen invalid host", "[:");

#నిర్వచనం_రద్దు CHECK_SUCCESS_AND_CLEANUP
#నిర్వచనం_రద్దు FAIL_TEST
}

స్థిర శూన్య
test_cert_parse(శూన్య)
{
	నిర్మాణం sshkey *cert;
	నిర్మాణం sshauthopt *opts, *expected;

#నిర్వచించు CHECK_SUCCESS_AND_CLEANUP() \
	చేయి { \
		compare_opts(opts, expected); \
		sshauthopt_free(expected); \
		sshauthopt_free(opts); \
		sshkey_free(cert); \
	} అయితే (0)
#నిర్వచించు FLAG_TEST(keybase, var) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_from_cert no_" keybase); \
		cert = ఎక్కించు_కీలకం("no_" keybase ".cert"); \
		expected = default_authkey_opts(); \
		expected->var = 0; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
		TEST_ప్రారంభం("sshauthopt_from_cert only_" keybase); \
		cert = ఎక్కించు_కీలకం("only_" keybase ".cert"); \
		expected = sshauthopt_new(); \
		ASSERT_PTR_NE(expected, ఖాళీ); \
		expected->var = 1; \
		opts = sshauthopt_from_cert(cert); \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
	} అయితే (0)
	FLAG_TEST("agentfwd", permit_agent_forwarding_flag);
	FLAG_TEST("portfwd", permit_పోర్టు_forwarding_flag);
	FLAG_TEST("pty", permit_pty_flag);
	FLAG_TEST("user_rc", permit_user_rc);
	FLAG_TEST("x11fwd", permit_x11_forwarding_flag);
#నిర్వచనం_రద్దు FLAG_TEST

	TEST_ప్రారంభం("sshauthopt_from_cert all permitted");
	cert = ఎక్కించు_కీలకం("all_permit.cert");
	expected = default_authkey_opts();
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_from_cert nothing permitted");
	cert = ఎక్కించు_కీలకం("no_permit.cert");
	expected = sshauthopt_new();
	ASSERT_PTR_NE(expected, ఖాళీ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_from_cert force-command");
	cert = ఎక్కించు_కీలకం("force_command.cert");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ఖాళీ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshauthopt_from_cert source-address");
	cert = ఎక్కించు_కీలకం("sourceaddr.cert");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ఖాళీ);
	opts = sshauthopt_from_cert(cert);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();
#నిర్వచనం_రద్దు CHECK_SUCCESS_AND_CLEANUP

#నిర్వచించు FAIL_TEST(keybase) \
	చేయి { \
		TEST_ప్రారంభం("sshauthopt_from_cert " keybase); \
		cert = ఎక్కించు_కీలకం(keybase ".cert"); \
		opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_EQ(opts, ఖాళీ); \
		sshkey_free(cert); \
		TEST_పూర్తి(); \
	} అయితే (0)
	FAIL_TEST("host");
	FAIL_TEST("bad_sourceaddr");
	FAIL_TEST("unknown_critical");
#నిర్వచనం_రద్దు FAIL_TEST
}

స్థిర శూన్య
test_విలీనం(శూన్య)
{
	నిర్మాణం sshkey *cert;
	నిర్మాణం sshauthopt *కీలకం_opts, *cert_opts, *విలీనం_opts, *expected;
	స్థిరరాశి అక్షరం *errstr;

	/*
	 * Prepare for a test by making some key and cert options and
	 * attempting to merge them.
	 */
#నిర్వచించు PREPARE(label, keyname, keywords) \
	చేయి { \
		expected = ఖాళీ; \
		TEST_ప్రారంభం("sshauthopt_merge " label); \
		cert = ఎక్కించు_కీలకం(keyname ".cert"); \
		cert_opts = sshauthopt_from_cert(cert); \
		ASSERT_PTR_NE(cert_opts, ఖాళీ); \
		కీలకం_opts = sshauthopt_parse(keywords, &errstr); \
		ఒకవేళ (errstr != ఖాళీ) \
			ASSERT_STRING_EQ(errstr, ""); \
		ASSERT_PTR_NE(కీలకం_opts, ఖాళీ); \
		విలీనం_opts = sshauthopt_విలీనం(కీలకం_opts, \
		    cert_opts, &errstr); \
	} అయితే (0)

	/* Cleanup stuff allocated by PREPARE() */
#నిర్వచించు CLEANUP() \
	చేయి { \
		sshauthopt_free(expected); \
		sshauthopt_free(విలీనం_opts); \
		sshauthopt_free(కీలకం_opts); \
		sshauthopt_free(cert_opts); \
		sshkey_free(cert); \
	} అయితే (0)

	/* Check the results of PREPARE() against expectation; calls CLEANUP */
#నిర్వచించు CHECK_SUCCESS_AND_CLEANUP() \
	చేయి { \
		ఒకవేళ (errstr != ఖాళీ) \
			ASSERT_STRING_EQ(errstr, ""); \
		compare_opts(విలీనం_opts, expected); \
		CLEANUP(); \
	} అయితే (0)

	/* Check a single case of merging of flag options */
#నిర్వచించు FLAG_CASE(keybase, label, keyname, keywords, mostly_off, \
	    rflag, var, val) \
	చేయి { \
		PREPARE(keybase " " label, keyname, keywords); \
		expected = mostly_off ? \
		    sshauthopt_new() : default_authkey_opts(); \
		ASSERT_PTR_NE(expected, ఖాళీ); \
		expected->restricted = rflag; \
		expected->var = val; \
		CHECK_SUCCESS_AND_CLEANUP(); \
		TEST_పూర్తి(); \
	} అయితే (0)

	/*
	 * Fairly exhaustive exercise of a flag option. Tests
	 * option both set and clear in certificate, set and clear in
	 * authorized_keys and set and cleared via restrict keyword.
	 */
#నిర్వచించు FLAG_TEST(keybase, keyword, var) \
	చేయి { \
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
	} అయితే (0)
	FLAG_TEST("portfwd", "port-forwarding", permit_పోర్టు_forwarding_flag);
	FLAG_TEST("agentfwd", "agent-forwarding", permit_agent_forwarding_flag);
	FLAG_TEST("pty", "pty", permit_pty_flag);
	FLAG_TEST("user_rc", "user-rc", permit_user_rc);
	FLAG_TEST("x11fwd", "x11-forwarding", permit_x11_forwarding_flag);
#నిర్వచనం_రద్దు FLAG_TEST

	PREPARE("source-address both", "sourceaddr", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ఖాళీ);
	expected->required_from_host_కీలకాలు = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_కీలకాలు, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("source-address none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("source-address keys", "all_permit", "from=\"127.0.0.1\"");
	expected = default_authkey_opts();
	expected->required_from_host_కీలకాలు = strdup("127.0.0.1");
	ASSERT_PTR_NE(expected->required_from_host_కీలకాలు, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("source-address cert", "sourceaddr", "");
	expected = default_authkey_opts();
	expected->required_from_host_cert = strdup("127.0.0.1/32,::1/128");
	ASSERT_PTR_NE(expected->required_from_host_cert, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("force-command both", "force_command", "command=\"foo\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("force-command none", "all_permit", "");
	expected = default_authkey_opts();
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("force-command keys", "all_permit", "command=\"bar\"");
	expected = default_authkey_opts();
	expected->force_command = strdup("bar");
	ASSERT_PTR_NE(expected->force_command, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("force-command cert", "force_command", "");
	expected = default_authkey_opts();
	expected->force_command = strdup("foo");
	ASSERT_PTR_NE(expected->force_command, ఖాళీ);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("force-command mismatch", "force_command", "command=\"bar\"");
	ASSERT_PTR_EQ(విలీనం_opts, ఖాళీ);
	CLEANUP();
	TEST_పూర్తి();

	PREPARE("tunnel", "all_permit", "tunnel=\"6\"");
	expected = default_authkey_opts();
	expected->force_tun_device = 6;
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("permitopen", "all_permit",
	    "permitopen=\"127.0.0.1:*\",permitopen=\"127.0.0.1:123\"");
	expected = default_authkey_opts();
	expected->permitopen = commasplit("127.0.0.1:*,127.0.0.1:123",
	    &expected->npermitopen);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();

	PREPARE("environment", "all_permit",
	    "environment=\"foo=a\",environment=\"bar=b\"");
	expected = default_authkey_opts();
	expected->env = commasplit("foo=a,bar=b", &expected->nenv);
	CHECK_SUCCESS_AND_CLEANUP();
	TEST_పూర్తి();
}

శూన్య
tests(శూన్య)
{
	బాహ్య అక్షరం *__progname;
	LogLevel ll = test_is_verbose() ?
	    SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_QUIET;

	/* test_cert_parse() are a bit spammy to error() by default... */
	log_init(__progname, ll, SYSLOG_FACILITY_USER, 1);

	test_authkeys_parse();
	test_cert_parse();
	test_విలీనం();
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
