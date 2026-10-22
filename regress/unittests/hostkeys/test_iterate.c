/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "hostfile.h"

সংরচনা expected {
	ধ্রুব বর্ণ *চাবি_file;		/* Path for key, NULL for none */
	পূর্ণাঙ্ক no_parse_status;		/* Expected status w/o key parsing */
	পূর্ণাঙ্ক no_parse_keytype;		/* Expected keytype w/o key parsing */
	পূর্ণাঙ্ক match_host_p;		/* Match 'prometheus.example.com' */
	পূর্ণাঙ্ক match_host_s;		/* Match 'sisyphus.example.com' */
	পূর্ণাঙ্ক match_ipv4;			/* Match '192.0.2.1' */
	পূর্ণাঙ্ক match_ipv6;			/* Match '2001:db8::1' */
	পূর্ণাঙ্ক match_flags;		/* Expected flags from match */
	সংরচনা hostkey_foreach_সারি l;	/* Expected line contents */
};

সংরচনা cbctx {
	ধ্রুব সংরচনা expected *expected;
	size_t nexpected;
	size_t i;
	পূর্ণাঙ্ক flags;
	পূর্ণাঙ্ক match_host_p;
	পূর্ণাঙ্ক match_host_s;
	পূর্ণাঙ্ক match_ipv4;
	পূর্ণাঙ্ক match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
স্থির পূর্ণাঙ্ক
check(সংরচনা hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	সংরচনা cbctx *ctx = (সংরচনা cbctx *)_ctx;
	ধ্রুব সংরচনা expected *expected;
	পূর্ণাঙ্ক parse_চাবি = (ctx->flags & HKF_WANT_PARSE_চাবি) != 0;
	ধ্রুব পূর্ণাঙ্ক matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	পূর্ণাঙ্ক expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	প্রতি (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		যদি (!matching)
			ভঙ্গ;
		যদি (ctx->match_host_p && expected->match_host_p)
			ভঙ্গ;
		যদি (ctx->match_host_s && expected->match_host_s)
			ভঙ্গ;
		যদি (ctx->match_ipv4 && expected->match_ipv4)
			ভঙ্গ;
		যদি (ctx->match_ipv6 && expected->match_ipv6)
			ভঙ্গ;
	}
	expected_status = (parse_চাবি || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) কুরু { \
		যদি (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			যদি (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} যাবত্ (0)
	expected_keytype = (parse_চাবি || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	যদি (expected->l.keytype == চাবি_RSA ||
	    expected->no_parse_keytype == চাবি_RSA ||
	    expected->l.keytype == চাবি_ECDSA ||
	    expected->no_parse_keytype == চাবি_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	যদি (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = চাবি_UNSPEC;
		parse_চাবি = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, রিক্ত); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	যদি (expected->l.সারি != রিক্ত)
		ASSERT_STRING_EQ(l->সারি, expected->l.সারি);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	যদি (expected->l.hosts != রিক্ত)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	যদি (expected->l.rawkey != রিক্ত)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	যদি (parse_চাবি) {
		যদি (expected->l.চাবি == রিক্ত)
			ASSERT_PTR_EQ(l->চাবি, রিক্ত);
		যদি (expected->l.চাবি != রিক্ত) {
			ASSERT_PTR_NE(l->চাবি, রিক্ত);
			ASSERT_INT_EQ(sshkey_equal(l->চাবি, expected->l.চাবি), 1);
		}
	}
	যদি (parse_চাবি && l->comment != রিক্ত && expected->l.comment != রিক্ত)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	প্রত্যাগম 0;
}

/* Loads public keys for a set of expected results */
স্থির শূন্য
prepare_expected(সংরচনা expected *expected, size_t n)
{
	size_t i;

	প্রতি (i = 0; i < n; i++) {
		যদি (expected[i].চাবি_file == রিক্ত)
			অনুবর্ত;
#ifndef WITH_OPENSSL
		বিকল্প (expected[i].l.keytype) {
		পক্ষ চাবি_RSA:
		পক্ষ চাবি_ECDSA:
			অনুবর্ত;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].চাবি_file), &expected[i].l.চাবি,
		    রিক্ত), 0);
	}
}

স্থির শূন্য
cleanup_expected(সংরচনা expected *expected, size_t n)
{
	size_t i;

	প্রতি (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.চাবি);
		expected[i].l.চাবি = রিক্ত;
	}
}

সংরচনা expected expected_full[] = {
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		রিক্ত,				/* hosts text */
		রিক্ত,				/* raw key, optional */
		চাবি_UNSPEC,			/* key type */
		রিক্ত,				/* deserialised key */
		রিক্ত,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		2,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		3,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		4,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		7,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		8,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		9,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		12,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		13,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		রিক্ত,
		14,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		রিক্ত,
		17,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		রিক্ত,
		18,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		রিক্ত,
		19,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		রিক্ত,
		21,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		রিক্ত,
		22,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		রিক্ত,
		23,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		রিক্ত,
		24,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		রিক্ত,
		25,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		রিক্ত,
		26,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		রিক্ত,
		27,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		রিক্ত,
		28,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		রিক্ত,
		29,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_RSA,
		রিক্ত,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		33,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_REVOKE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_ED25519,
		রিক্ত,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		রিক্ত,
		34,
		HKF_STATUS_OK,
		0,
		রিক্ত,
		MRK_CA,
		"prometheus.example.com",
		রিক্ত,
		চাবি_ECDSA,
		রিক্ত,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, 0, 0, 0, -1, {
		রিক্ত,
		37,
		HKF_STATUS_INVALID,
		0,
		রিক্ত,
		MRK_ERROR,
		রিক্ত,
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		38,
		HKF_STATUS_INVALID,
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		রিক্ত,
		39,
		HKF_STATUS_INVALID,
		0,
		রিক্ত,
		MRK_NONE,
		"prometheus.example.com",
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, HKF_STATUS_OK, চাবি_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,
		রিক্ত,
		0,
	} },
	{ রিক্ত, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		রিক্ত,
		41,
		HKF_STATUS_INVALID,
		0,
		রিক্ত,
		MRK_NONE,
		"sisyphus.example.com",
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,	/* filled at runtime */
		রিক্ত,
		0,
	} },
	{ রিক্ত, HKF_STATUS_OK, চাবি_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		রিক্ত,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		রিক্ত,
		MRK_NONE,
		"prometheus.example.com",
		রিক্ত,
		চাবি_UNSPEC,
		রিক্ত,	/* filled at runtime */
		রিক্ত,
		0,
	} },
};

শূন্য test_iterate(শূন্য);

শূন্য
test_iterate(শূন্য)
{
	সংরচনা cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_চাবি;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, রিক্ত, রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, রিক্ত, রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", রিক্ত, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
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
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_চাবি;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, পরিমাণ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = পরিমাণ(expected_full)/পরিমাণ(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_চাবি;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

