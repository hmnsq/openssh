/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
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
#ضمن "hostfile.h"

بنية expected {
	ثابت حرف *مبودي_file;		/* Path for key, NULL for none */
	صحيح no_parse_status;		/* Expected status w/o key parsing */
	صحيح no_parse_keytype;		/* Expected keytype w/o key parsing */
	صحيح match_host_p;		/* Match 'prometheus.example.com' */
	صحيح match_host_s;		/* Match 'sisyphus.example.com' */
	صحيح match_ipv4;			/* Match '192.0.2.1' */
	صحيح match_ipv6;			/* Match '2001:db8::1' */
	صحيح match_flags;		/* Expected flags from match */
	بنية hostkey_foreach_لي l;	/* Expected line contents */
};

بنية cbctx {
	ثابت بنية expected *expected;
	size_t nexpected;
	size_t i;
	صحيح flags;
	صحيح match_host_p;
	صحيح match_host_s;
	صحيح match_ipv4;
	صحيح match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ساكن صحيح
check(بنية hostkey_foreach_لي *l, فراغ *_ctx)
{
	بنية cbctx *ctx = (بنية cbctx *)_ctx;
	ثابت بنية expected *expected;
	صحيح parse_مبودي = (ctx->flags & HKF_WANT_PARSE_مبودي) != 0;
	ثابت صحيح matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	صحيح expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	لكل (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		إذا (!matching)
			اكسر;
		إذا (ctx->match_host_p && expected->match_host_p)
			اكسر;
		إذا (ctx->match_host_s && expected->match_host_s)
			اكسر;
		إذا (ctx->match_ipv4 && expected->match_ipv4)
			اكسر;
		إذا (ctx->match_ipv6 && expected->match_ipv6)
			اكسر;
	}
	expected_status = (parse_مبودي || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) افعل { \
		إذا (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			إذا (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} طالما (0)
	expected_keytype = (parse_مبودي || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	إذا (expected->l.keytype == مبودي_RSA ||
	    expected->no_parse_keytype == مبودي_RSA ||
	    expected->l.keytype == مبودي_ECDSA ||
	    expected->no_parse_keytype == مبودي_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	إذا (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = مبودي_UNSPEC;
		parse_مبودي = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, عدم); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	إذا (expected->l.لي != عدم)
		ASSERT_STRING_EQ(l->لي, expected->l.لي);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	إذا (expected->l.hosts != عدم)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	إذا (expected->l.rawkey != عدم)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	إذا (parse_مبودي) {
		إذا (expected->l.مبودي == عدم)
			ASSERT_PTR_EQ(l->مبودي, عدم);
		إذا (expected->l.مبودي != عدم) {
			ASSERT_PTR_NE(l->مبودي, عدم);
			ASSERT_INT_EQ(sshkey_equal(l->مبودي, expected->l.مبودي), 1);
		}
	}
	إذا (parse_مبودي && l->comment != عدم && expected->l.comment != عدم)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	أرجع 0;
}

/* Loads public keys for a set of expected results */
ساكن فراغ
prepare_expected(بنية expected *expected, size_t n)
{
	size_t i;

	لكل (i = 0; i < n; i++) {
		إذا (expected[i].مبودي_file == عدم)
			استمر;
#ifndef WITH_OPENSSL
		بدل (expected[i].l.keytype) {
		حالة مبودي_RSA:
		حالة مبودي_ECDSA:
			استمر;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].مبودي_file), &expected[i].l.مبودي,
		    عدم), 0);
	}
}

ساكن فراغ
cleanup_expected(بنية expected *expected, size_t n)
{
	size_t i;

	لكل (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.مبودي);
		expected[i].l.مبودي = عدم;
	}
}

بنية expected expected_full[] = {
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		عدم,				/* hosts text */
		عدم,				/* raw key, optional */
		مبودي_UNSPEC,			/* key type */
		عدم,				/* deserialised key */
		عدم,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		2,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		3,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		4,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		7,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		8,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		9,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		12,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		13,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		عدم,
		14,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		عدم,
		17,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		عدم,
		18,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		عدم,
		19,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		عدم,
		21,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		عدم,
		22,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		عدم,
		23,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		عدم,
		24,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		عدم,
		25,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		عدم,
		26,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		عدم,
		27,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		عدم,
		28,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		عدم,
		29,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_NONE,
		عدم,
		عدم,
		مبودي_RSA,
		عدم,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		33,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_REVOKE,
		"sisyphus.example.com",
		عدم,
		مبودي_ED25519,
		عدم,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		عدم,
		34,
		HKF_STATUS_OK,
		0,
		عدم,
		MRK_CA,
		"prometheus.example.com",
		عدم,
		مبودي_ECDSA,
		عدم,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, 0, 0, 0, -1, {
		عدم,
		37,
		HKF_STATUS_INVALID,
		0,
		عدم,
		MRK_ERROR,
		عدم,
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		38,
		HKF_STATUS_INVALID,
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		عدم,
		39,
		HKF_STATUS_INVALID,
		0,
		عدم,
		MRK_NONE,
		"prometheus.example.com",
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, HKF_STATUS_OK, مبودي_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_UNSPEC,
		عدم,
		عدم,
		0,
	} },
	{ عدم, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		عدم,
		41,
		HKF_STATUS_INVALID,
		0,
		عدم,
		MRK_NONE,
		"sisyphus.example.com",
		عدم,
		مبودي_UNSPEC,
		عدم,	/* filled at runtime */
		عدم,
		0,
	} },
	{ عدم, HKF_STATUS_OK, مبودي_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		عدم,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		عدم,
		MRK_NONE,
		"prometheus.example.com",
		عدم,
		مبودي_UNSPEC,
		عدم,	/* filled at runtime */
		عدم,
		0,
	} },
};

فراغ test_iterate(فراغ);

فراغ
test_iterate(فراغ)
{
	بنية cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_PARSE_مبودي;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, عدم, عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, عدم, عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", عدم, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
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
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_PARSE_مبودي;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = حجم(expected_full)/حجم(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_مبودي;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

