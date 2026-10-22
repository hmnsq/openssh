/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"

ସଂରଚନା expected {
	ଅଚଳ ଅକ୍ଷର *ଚାବି_file;		/* Path for key, NULL for none */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା no_parse_status;		/* Expected status w/o key parsing */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା no_parse_keytype;		/* Expected keytype w/o key parsing */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_host_p;		/* Match 'prometheus.example.com' */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_host_s;		/* Match 'sisyphus.example.com' */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_ipv4;			/* Match '192.0.2.1' */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_ipv6;			/* Match '2001:db8::1' */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_flags;		/* Expected flags from match */
	ସଂରଚନା hostkey_foreach_ଧାଡ଼ି l;	/* Expected line contents */
};

ସଂରଚନା cbctx {
	ଅଚଳ ସଂରଚନା expected *expected;
	size_t nexpected;
	size_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_host_p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_host_s;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_ipv4;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *_ctx)
{
	ସଂରଚନା cbctx *ctx = (ସଂରଚନା cbctx *)_ctx;
	ଅଚଳ ସଂରଚନା expected *expected;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା parse_ଚାବି = (ctx->flags & HKF_WANT_PARSE_ଚାବି) != 0;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	ପାଇଁ (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		ଯଦି (!matching)
			ଭାଙ୍ଗ;
		ଯଦି (ctx->match_host_p && expected->match_host_p)
			ଭାଙ୍ଗ;
		ଯଦି (ctx->match_host_s && expected->match_host_s)
			ଭାଙ୍ଗ;
		ଯଦି (ctx->match_ipv4 && expected->match_ipv4)
			ଭାଙ୍ଗ;
		ଯଦି (ctx->match_ipv6 && expected->match_ipv6)
			ଭାଙ୍ଗ;
	}
	expected_status = (parse_ଚାବି || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) କର { \
		ଯଦି (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			ଯଦି (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} ଯେତେବେଳେ (0)
	expected_keytype = (parse_ଚାବି || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	ଯଦି (expected->l.keytype == ଚାବି_RSA ||
	    expected->no_parse_keytype == ଚାବି_RSA ||
	    expected->l.keytype == ଚାବି_ECDSA ||
	    expected->no_parse_keytype == ଚାବି_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	ଯଦି (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = ଚାବି_UNSPEC;
		parse_ଚାବି = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, ଖାଲି); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	ଯଦି (expected->l.ଧାଡ଼ି != ଖାଲି)
		ASSERT_STRING_EQ(l->ଧାଡ଼ି, expected->l.ଧାଡ଼ି);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	ଯଦି (expected->l.hosts != ଖାଲି)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	ଯଦି (expected->l.rawkey != ଖାଲି)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	ଯଦି (parse_ଚାବି) {
		ଯଦି (expected->l.ଚାବି == ଖାଲି)
			ASSERT_PTR_EQ(l->ଚାବି, ଖାଲି);
		ଯଦି (expected->l.ଚାବି != ଖାଲି) {
			ASSERT_PTR_NE(l->ଚାବି, ଖାଲି);
			ASSERT_INT_EQ(sshkey_equal(l->ଚାବି, expected->l.ଚାବି), 1);
		}
	}
	ଯଦି (parse_ଚାବି && l->comment != ଖାଲି && expected->l.comment != ଖାଲି)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	ଫେରନ୍ତୁ 0;
}

/* Loads public keys for a set of expected results */
ସ୍ଥିର ଶୂନ୍ୟ
prepare_expected(ସଂରଚନା expected *expected, size_t n)
{
	size_t i;

	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି (expected[i].ଚାବି_file == ଖାଲି)
			ଜାରି;
#ifndef WITH_OPENSSL
		ବାଛ (expected[i].l.keytype) {
		ସ୍ଥିତି ଚାବି_RSA:
		ସ୍ଥିତି ଚାବି_ECDSA:
			ଜାରି;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].ଚାବି_file), &expected[i].l.ଚାବି,
		    ଖାଲି), 0);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
cleanup_expected(ସଂରଚନା expected *expected, size_t n)
{
	size_t i;

	ପାଇଁ (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.ଚାବି);
		expected[i].l.ଚାବି = ଖାଲି;
	}
}

ସଂରଚନା expected expected_full[] = {
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ଖାଲି,				/* hosts text */
		ଖାଲି,				/* raw key, optional */
		ଚାବି_UNSPEC,			/* key type */
		ଖାଲି,				/* deserialised key */
		ଖାଲି,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		2,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		3,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		4,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		7,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		8,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		9,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		12,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		13,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ଖାଲି,
		14,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ଖାଲି,
		17,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ଖାଲି,
		18,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ଖାଲି,
		19,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ଖାଲି,
		21,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ଖାଲି,
		22,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ଖାଲି,
		23,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ଖାଲି,
		24,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ଖାଲି,
		25,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ଖାଲି,
		26,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ଖାଲି,
		27,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ଖାଲି,
		28,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ଖାଲି,
		29,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_RSA,
		ଖାଲି,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		33,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_REVOKE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_ED25519,
		ଖାଲି,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ଖାଲି,
		34,
		HKF_STATUS_OK,
		0,
		ଖାଲି,
		MRK_CA,
		"prometheus.example.com",
		ଖାଲି,
		ଚାବି_ECDSA,
		ଖାଲି,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, 0, 0, 0, -1, {
		ଖାଲି,
		37,
		HKF_STATUS_INVALID,
		0,
		ଖାଲି,
		MRK_ERROR,
		ଖାଲି,
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		38,
		HKF_STATUS_INVALID,
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ଖାଲି,
		39,
		HKF_STATUS_INVALID,
		0,
		ଖାଲି,
		MRK_NONE,
		"prometheus.example.com",
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, HKF_STATUS_OK, ଚାବି_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ଖାଲି,
		41,
		HKF_STATUS_INVALID,
		0,
		ଖାଲି,
		MRK_NONE,
		"sisyphus.example.com",
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,	/* filled at runtime */
		ଖାଲି,
		0,
	} },
	{ ଖାଲି, HKF_STATUS_OK, ଚାବି_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ଖାଲି,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ଖାଲି,
		MRK_NONE,
		"prometheus.example.com",
		ଖାଲି,
		ଚାବି_UNSPEC,
		ଖାଲି,	/* filled at runtime */
		ଖାଲି,
		0,
	} },
};

ଶୂନ୍ୟ test_iterate(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
test_iterate(ଶୂନ୍ୟ)
{
	ସଂରଚନା cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ଚାବି;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ଖାଲି, ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ଖାଲି, ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ଖାଲି, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ଚାବି;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, ଆକାର(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ଆକାର(expected_full)/ଆକାର(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_ଚାବି;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

