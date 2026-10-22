/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
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
#شامل "hostfile.h"

ساختار expected {
	ثابت نویسه *کلید_file;		/* Path for key, NULL for none */
	صحیح no_parse_status;		/* Expected status w/o key parsing */
	صحیح no_parse_keytype;		/* Expected keytype w/o key parsing */
	صحیح match_host_p;		/* Match 'prometheus.example.com' */
	صحیح match_host_s;		/* Match 'sisyphus.example.com' */
	صحیح match_ipv4;			/* Match '192.0.2.1' */
	صحیح match_ipv6;			/* Match '2001:db8::1' */
	صحیح match_flags;		/* Expected flags from match */
	ساختار hostkey_foreach_سطر l;	/* Expected line contents */
};

ساختار cbctx {
	ثابت ساختار expected *expected;
	size_t nexpected;
	size_t i;
	صحیح flags;
	صحیح match_host_p;
	صحیح match_host_s;
	صحیح match_ipv4;
	صحیح match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ایستا صحیح
check(ساختار hostkey_foreach_سطر *l, تهی *_ctx)
{
	ساختار cbctx *ctx = (ساختار cbctx *)_ctx;
	ثابت ساختار expected *expected;
	صحیح parse_کلید = (ctx->flags & HKF_WANT_PARSE_کلید) != 0;
	ثابت صحیح matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	صحیح expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	برای (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		اگر (!matching)
			بشکن;
		اگر (ctx->match_host_p && expected->match_host_p)
			بشکن;
		اگر (ctx->match_host_s && expected->match_host_s)
			بشکن;
		اگر (ctx->match_ipv4 && expected->match_ipv4)
			بشکن;
		اگر (ctx->match_ipv6 && expected->match_ipv6)
			بشکن;
	}
	expected_status = (parse_کلید || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) انجامبده { \
		اگر (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			اگر (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} وقتی (0)
	expected_keytype = (parse_کلید || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	اگر (expected->l.keytype == کلید_RSA ||
	    expected->no_parse_keytype == کلید_RSA ||
	    expected->l.keytype == کلید_ECDSA ||
	    expected->no_parse_keytype == کلید_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	اگر (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = کلید_UNSPEC;
		parse_کلید = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, پوچ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	اگر (expected->l.سطر != پوچ)
		ASSERT_STRING_EQ(l->سطر, expected->l.سطر);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	اگر (expected->l.hosts != پوچ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	اگر (expected->l.rawkey != پوچ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	اگر (parse_کلید) {
		اگر (expected->l.کلید == پوچ)
			ASSERT_PTR_EQ(l->کلید, پوچ);
		اگر (expected->l.کلید != پوچ) {
			ASSERT_PTR_NE(l->کلید, پوچ);
			ASSERT_INT_EQ(sshkey_equal(l->کلید, expected->l.کلید), 1);
		}
	}
	اگر (parse_کلید && l->comment != پوچ && expected->l.comment != پوچ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	بازگشت 0;
}

/* Loads public keys for a set of expected results */
ایستا تهی
prepare_expected(ساختار expected *expected, size_t n)
{
	size_t i;

	برای (i = 0; i < n; i++) {
		اگر (expected[i].کلید_file == پوچ)
			ادامه;
#ifndef WITH_OPENSSL
		انتخاب (expected[i].l.keytype) {
		حالت کلید_RSA:
		حالت کلید_ECDSA:
			ادامه;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].کلید_file), &expected[i].l.کلید,
		    پوچ), 0);
	}
}

ایستا تهی
cleanup_expected(ساختار expected *expected, size_t n)
{
	size_t i;

	برای (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.کلید);
		expected[i].l.کلید = پوچ;
	}
}

ساختار expected expected_full[] = {
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		پوچ,				/* hosts text */
		پوچ,				/* raw key, optional */
		کلید_UNSPEC,			/* key type */
		پوچ,				/* deserialised key */
		پوچ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		2,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		3,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		4,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		7,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		8,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		9,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		12,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		13,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		پوچ,
		14,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		پوچ,
		17,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		پوچ,
		18,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		پوچ,
		19,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		پوچ,
		21,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		پوچ,
		22,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		پوچ,
		23,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		پوچ,
		24,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		پوچ,
		25,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		پوچ,
		26,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		پوچ,
		27,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		پوچ,
		28,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		پوچ,
		29,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_RSA,
		پوچ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		33,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_REVOKE,
		"sisyphus.example.com",
		پوچ,
		کلید_ED25519,
		پوچ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		پوچ,
		34,
		HKF_STATUS_OK,
		0,
		پوچ,
		MRK_CA,
		"prometheus.example.com",
		پوچ,
		کلید_ECDSA,
		پوچ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, 0, 0, 0, -1, {
		پوچ,
		37,
		HKF_STATUS_INVALID,
		0,
		پوچ,
		MRK_ERROR,
		پوچ,
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		38,
		HKF_STATUS_INVALID,
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		پوچ,
		39,
		HKF_STATUS_INVALID,
		0,
		پوچ,
		MRK_NONE,
		"prometheus.example.com",
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, HKF_STATUS_OK, کلید_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_UNSPEC,
		پوچ,
		پوچ,
		0,
	} },
	{ پوچ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		پوچ,
		41,
		HKF_STATUS_INVALID,
		0,
		پوچ,
		MRK_NONE,
		"sisyphus.example.com",
		پوچ,
		کلید_UNSPEC,
		پوچ,	/* filled at runtime */
		پوچ,
		0,
	} },
	{ پوچ, HKF_STATUS_OK, کلید_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		پوچ,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		پوچ,
		MRK_NONE,
		"prometheus.example.com",
		پوچ,
		کلید_UNSPEC,
		پوچ,	/* filled at runtime */
		پوچ,
		0,
	} },
};

تهی test_iterate(تهی);

تهی
test_iterate(تهی)
{
	ساختار cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_PARSE_کلید;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, پوچ, پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, پوچ, پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", پوچ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
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
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_PARSE_کلید;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, اندازه(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = اندازه(expected_full)/اندازه(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_کلید;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

