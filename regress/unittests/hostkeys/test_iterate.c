/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
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
#అన్తర్భావ "hostfile.h"

నిర్మాణం expected {
	స్థిరరాశి అక్షరం *కీలకం_file;		/* Path for key, NULL for none */
	పూర్ణాంకం no_parse_స్థితి;		/* Expected status w/o key parsing */
	పూర్ణాంకం no_parse_keytype;		/* Expected keytype w/o key parsing */
	పూర్ణాంకం సరిపోలిక_host_p;		/* Match 'prometheus.example.com' */
	పూర్ణాంకం సరిపోలిక_host_s;		/* Match 'sisyphus.example.com' */
	పూర్ణాంకం సరిపోలిక_ipv4;			/* Match '192.0.2.1' */
	పూర్ణాంకం సరిపోలిక_ipv6;			/* Match '2001:db8::1' */
	పూర్ణాంకం సరిపోలిక_flags;		/* Expected flags from match */
	నిర్మాణం hostkey_foreach_పంక్తి l;	/* Expected line contents */
};

నిర్మాణం cbctx {
	స్థిరరాశి నిర్మాణం expected *expected;
	కొలత_t nexpected;
	కొలత_t i;
	పూర్ణాంకం flags;
	పూర్ణాంకం సరిపోలిక_host_p;
	పూర్ణాంకం సరిపోలిక_host_s;
	పూర్ణాంకం సరిపోలిక_ipv4;
	పూర్ణాంకం సరిపోలిక_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
స్థిర పూర్ణాంకం
check(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *_ctx)
{
	నిర్మాణం cbctx *ctx = (నిర్మాణం cbctx *)_ctx;
	స్థిరరాశి నిర్మాణం expected *expected;
	పూర్ణాంకం parse_కీలకం = (ctx->flags & HKF_WANT_PARSE_కీలకం) != 0;
	స్థిరరాశి పూర్ణాంకం matching = (ctx->flags & HKF_WANT_సరిపోలిక) != 0;
	u_int expected_స్థితి, expected_సరిపోలిక;
	పూర్ణాంకం expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	కొరకు (;;) {
		ASSERT_కొలత_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		ఒకవేళ (!matching)
			ఆపు;
		ఒకవేళ (ctx->సరిపోలిక_host_p && expected->సరిపోలిక_host_p)
			ఆపు;
		ఒకవేళ (ctx->సరిపోలిక_host_s && expected->సరిపోలిక_host_s)
			ఆపు;
		ఒకవేళ (ctx->సరిపోలిక_ipv4 && expected->సరిపోలిక_ipv4)
			ఆపు;
		ఒకవేళ (ctx->సరిపోలిక_ipv6 && expected->సరిపోలిక_ipv6)
			ఆపు;
	}
	expected_స్థితి = (parse_కీలకం || expected->no_parse_స్థితి < 0) ?
	    expected->l.స్థితి_2 : (u_int)expected->no_parse_స్థితి;
	expected_సరిపోలిక = expected->l.సరిపోలిక;
#నిర్వచించు UPDATE_సరిపోలిక_స్థితి(x) చేయి { \
		ఒకవేళ (ctx->x && expected->x) { \
			expected_సరిపోలిక |= expected->x; \
			ఒకవేళ (expected_స్థితి == HKF_స్థితి_OK) \
				expected_స్థితి = HKF_స్థితి_MATCHED; \
		} \
	} అయితే (0)
	expected_keytype = (parse_కీలకం || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#నిర్వచితం_కాకపోతే WITH_OPENSSL
	ఒకవేళ (expected->l.keytype == కీలకం_RSA ||
	    expected->no_parse_keytype == కీలకం_RSA ||
	    expected->l.keytype == కీలకం_ECDSA ||
	    expected->no_parse_keytype == కీలకం_ECDSA)
		skip = 1;
#అయితే_ముగింపు /* WITH_OPENSSL */
	ఒకవేళ (skip) {
		expected_స్థితి = HKF_స్థితి_INVALID;
		expected_keytype = కీలకం_UNSPEC;
		parse_కీలకం = 0;
	}
	UPDATE_సరిపోలిక_స్థితి(సరిపోలిక_host_p);
	UPDATE_సరిపోలిక_స్థితి(సరిపోలిక_host_s);
	UPDATE_సరిపోలిక_స్థితి(సరిపోలిక_ipv4);
	UPDATE_సరిపోలిక_స్థితి(సరిపోలిక_ipv6);

	ASSERT_PTR_NE(l->మార్గం, ఖాళీ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->స్థితి_2, expected_స్థితి);
	ASSERT_U_INT_EQ(l->సరిపోలిక, expected_సరిపోలిక);
	/* Not all test entries contain fulltext */
	ఒకవేళ (expected->l.పంక్తి != ఖాళీ)
		ASSERT_STRING_EQ(l->పంక్తి, expected->l.పంక్తి);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	ఒకవేళ (expected->l.hosts != ఖాళీ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	ఒకవేళ (expected->l.rawkey != ఖాళీ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	ఒకవేళ (parse_కీలకం) {
		ఒకవేళ (expected->l.కీలకం == ఖాళీ)
			ASSERT_PTR_EQ(l->కీలకం, ఖాళీ);
		ఒకవేళ (expected->l.కీలకం != ఖాళీ) {
			ASSERT_PTR_NE(l->కీలకం, ఖాళీ);
			ASSERT_INT_EQ(sshkey_equal(l->కీలకం, expected->l.కీలకం), 1);
		}
	}
	ఒకవేళ (parse_కీలకం && l->comment != ఖాళీ && expected->l.comment != ఖాళీ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	తిరిగి 0;
}

/* Loads public keys for a set of expected results */
స్థిర శూన్య
prepare_expected(నిర్మాణం expected *expected, కొలత_t n)
{
	కొలత_t i;

	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ (expected[i].కీలకం_file == ఖాళీ)
			కొనసాగు;
#నిర్వచితం_కాకపోతే WITH_OPENSSL
		ఎంపిక (expected[i].l.keytype) {
		స్థితి కీలకం_RSA:
		స్థితి కీలకం_ECDSA:
			కొనసాగు;
		}
#అయితే_ముగింపు /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_ఎక్కించు_ప్రజా(
		    test_దత్తాంశం_file(expected[i].కీలకం_file), &expected[i].l.కీలకం,
		    ఖాళీ), 0);
	}
}

స్థిర శూన్య
cleanup_expected(నిర్మాణం expected *expected, కొలత_t n)
{
	కొలత_t i;

	కొరకు (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.కీలకం);
		expected[i].l.కీలకం = ఖాళీ;
	}
}

నిర్మాణం expected expected_నిండిన[] = {
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,				/* path, don't care */
		1,				/* line number */
		HKF_స్థితి_COMMENT,		/*స్థితి*/
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ఖాళీ,				/* hosts text */
		ఖాళీ,				/* raw key, optional */
		కీలకం_UNSPEC,			/* key type */
		ఖాళీ,				/* deserialised key */
		ఖాళీ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		2,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		3,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		4,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		5,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		6,
		HKF_స్థితి_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_సరిపోలిక_HOST, 0, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		7,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_సరిపోలిక_HOST, 0, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		8,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_సరిపోలిక_HOST, 0, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		9,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		10,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		11,
		HKF_స్థితి_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		12,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		13,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_HOST, HKF_సరిపోలిక_IP, HKF_సరిపోలిక_IP, -1, {
		ఖాళీ,
		14,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		15,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		16,
		HKF_స్థితి_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, -1, {
		ఖాళీ,
		17,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, -1, {
		ఖాళీ,
		18,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, -1, {
		ఖాళీ,
		19,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		20,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, 0, -1, {
		ఖాళీ,
		21,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, 0, -1, {
		ఖాళీ,
		22,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, -1, {
		ఖాళీ,
		23,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, 0, -1, {
		ఖాళీ,
		24,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, 0, -1, {
		ఖాళీ,
		25,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, -1, {
		ఖాళీ,
		26,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_సరిపోలిక_HOST|HKF_సరిపోలిక_HOST_HASHED, 0, 0, 0, -1, {
		ఖాళీ,
		27,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, 0, -1, {
		ఖాళీ,
		28,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_సరిపోలిక_IP|HKF_సరిపోలిక_IP_HASHED, -1, {
		ఖాళీ,
		29,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_RSA,
		ఖాళీ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		30,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		31,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		32,
		HKF_స్థితి_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		33,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_REVOKE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_ED25519,
		ఖాళీ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_సరిపోలిక_HOST, 0, 0, 0, -1, {
		ఖాళీ,
		34,
		HKF_స్థితి_OK,
		0,
		ఖాళీ,
		MRK_CA,
		"prometheus.example.com",
		ఖాళీ,
		కీలకం_ECDSA,
		ఖాళీ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		35,
		HKF_స్థితి_COMMENT,
		0,
		"",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		36,
		HKF_స్థితి_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, 0, 0, 0, -1, {
		ఖాళీ,
		37,
		HKF_స్థితి_INVALID,
		0,
		ఖాళీ,
		MRK_ERROR,
		ఖాళీ,
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		38,
		HKF_స్థితి_INVALID,
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, HKF_సరిపోలిక_HOST, 0, 0, 0, -1, {
		ఖాళీ,
		39,
		HKF_స్థితి_INVALID,
		0,
		ఖాళీ,
		MRK_NONE,
		"prometheus.example.com",
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, HKF_స్థితి_OK, కీలకం_ED25519, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		40,
		HKF_స్థితి_INVALID,	/* Would be ok if key not parsed */
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, -1, -1, 0, HKF_సరిపోలిక_HOST, 0, 0, -1, {
		ఖాళీ,
		41,
		HKF_స్థితి_INVALID,
		0,
		ఖాళీ,
		MRK_NONE,
		"sisyphus.example.com",
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,	/* filled at runtime */
		ఖాళీ,
		0,
	} },
	{ ఖాళీ, HKF_స్థితి_OK, కీలకం_RSA, HKF_సరిపోలిక_HOST, 0, 0, 0, -1, {
		ఖాళీ,
		42,
		HKF_స్థితి_INVALID,	/* Would be ok if key not parsed */
		0,
		ఖాళీ,
		MRK_NONE,
		"prometheus.example.com",
		ఖాళీ,
		కీలకం_UNSPEC,
		ఖాళీ,	/* filled at runtime */
		ఖాళీ,
		0,
	} },
};

శూన్య test_iterate(శూన్య);

శూన్య
test_iterate(శూన్య)
{
	నిర్మాణం cbctx ctx;

	TEST_ప్రారంభం("hostkeys_iterate all with key parse");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_PARSE_కీలకం;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, ఖాళీ, ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate all without key parse");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, ఖాళీ, ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify host 1");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	ctx.సరిపోలిక_host_p = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify host 2");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	ctx.సరిపోలిక_host_s = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match host 1");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	ctx.సరిపోలిక_host_p = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match host 2");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	ctx.సరిపోలిక_host_s = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify host missing");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match host missing");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ఖాళీ, ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	ctx.సరిపోలిక_ipv4 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	ctx.సరిపోలిక_ipv6 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match IPv4");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	ctx.సరిపోలిక_ipv4 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match IPv6");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	ctx.సరిపోలిక_ipv6 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match addr missing");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = 0;
	ctx.సరిపోలిక_host_s = 1;
	ctx.సరిపోలిక_ipv4 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక;
	ctx.సరిపోలిక_host_p = 1;
	ctx.సరిపోలిక_ipv6 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_PARSE_కీలకం;
	ctx.సరిపోలిక_host_s = 1;
	ctx.సరిపోలిక_ipv4 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();

	TEST_ప్రారంభం("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, పరిమాణం(ctx));
	ctx.expected = expected_నిండిన;
	ctx.nexpected = పరిమాణం(expected_నిండిన)/పరిమాణం(*expected_నిండిన);
	ctx.flags = HKF_WANT_సరిపోలిక|HKF_WANT_PARSE_కీలకం;
	ctx.సరిపోలిక_host_p = 1;
	ctx.సరిపోలిక_ipv6 = 1;
	prepare_expected(expected_నిండిన, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_దత్తాంశం_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_నిండిన, ctx.nexpected);
	TEST_పూర్తి();
}

