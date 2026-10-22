/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "hostfile.h"

கட்டமைப்பு expected {
	மாறிலி எழுத்து *சாவி_file;		/* Path for key, NULL for none */
	முழு no_parse_status;		/* Expected status w/o key parsing */
	முழு no_parse_keytype;		/* Expected keytype w/o key parsing */
	முழு match_host_p;		/* Match 'prometheus.example.com' */
	முழு match_host_s;		/* Match 'sisyphus.example.com' */
	முழு match_ipv4;			/* Match '192.0.2.1' */
	முழு match_ipv6;			/* Match '2001:db8::1' */
	முழு match_flags;		/* Expected flags from match */
	கட்டமைப்பு hostkey_foreach_வரி l;	/* Expected line contents */
};

கட்டமைப்பு cbctx {
	மாறிலி கட்டமைப்பு expected *expected;
	size_t nexpected;
	size_t i;
	முழு flags;
	முழு match_host_p;
	முழு match_host_s;
	முழு match_ipv4;
	முழு match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
நிலையான முழு
check(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *_ctx)
{
	கட்டமைப்பு cbctx *ctx = (கட்டமைப்பு cbctx *)_ctx;
	மாறிலி கட்டமைப்பு expected *expected;
	முழு parse_சாவி = (ctx->flags & HKF_WANT_PARSE_சாவி) != 0;
	மாறிலி முழு matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	முழு expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	க்கு (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		எனில் (!matching)
			நிறுத்து;
		எனில் (ctx->match_host_p && expected->match_host_p)
			நிறுத்து;
		எனில் (ctx->match_host_s && expected->match_host_s)
			நிறுத்து;
		எனில் (ctx->match_ipv4 && expected->match_ipv4)
			நிறுத்து;
		எனில் (ctx->match_ipv6 && expected->match_ipv6)
			நிறுத்து;
	}
	expected_status = (parse_சாவி || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) செய் { \
		எனில் (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			எனில் (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} போது (0)
	expected_keytype = (parse_சாவி || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	எனில் (expected->l.keytype == சாவி_RSA ||
	    expected->no_parse_keytype == சாவி_RSA ||
	    expected->l.keytype == சாவி_ECDSA ||
	    expected->no_parse_keytype == சாவி_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	எனில் (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = சாவி_UNSPEC;
		parse_சாவி = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, வெற்று); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	எனில் (expected->l.வரி != வெற்று)
		ASSERT_STRING_EQ(l->வரி, expected->l.வரி);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	எனில் (expected->l.hosts != வெற்று)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	எனில் (expected->l.rawkey != வெற்று)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	எனில் (parse_சாவி) {
		எனில் (expected->l.சாவி == வெற்று)
			ASSERT_PTR_EQ(l->சாவி, வெற்று);
		எனில் (expected->l.சாவி != வெற்று) {
			ASSERT_PTR_NE(l->சாவி, வெற்று);
			ASSERT_INT_EQ(sshkey_equal(l->சாவி, expected->l.சாவி), 1);
		}
	}
	எனில் (parse_சாவி && l->comment != வெற்று && expected->l.comment != வெற்று)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	திரும்பு 0;
}

/* Loads public keys for a set of expected results */
நிலையான வெறுமை
prepare_expected(கட்டமைப்பு expected *expected, size_t n)
{
	size_t i;

	க்கு (i = 0; i < n; i++) {
		எனில் (expected[i].சாவி_file == வெற்று)
			தொடர்;
#ifndef WITH_OPENSSL
		தேர்வு (expected[i].l.keytype) {
		நிலை சாவி_RSA:
		நிலை சாவி_ECDSA:
			தொடர்;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].சாவி_file), &expected[i].l.சாவி,
		    வெற்று), 0);
	}
}

நிலையான வெறுமை
cleanup_expected(கட்டமைப்பு expected *expected, size_t n)
{
	size_t i;

	க்கு (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.சாவி);
		expected[i].l.சாவி = வெற்று;
	}
}

கட்டமைப்பு expected expected_full[] = {
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		வெற்று,				/* hosts text */
		வெற்று,				/* raw key, optional */
		சாவி_UNSPEC,			/* key type */
		வெற்று,				/* deserialised key */
		வெற்று,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		2,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		3,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		4,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		7,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		8,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		9,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		12,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		13,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		வெற்று,
		14,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		வெற்று,
		17,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		வெற்று,
		18,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		வெற்று,
		19,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		வெற்று,
		21,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		வெற்று,
		22,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		வெற்று,
		23,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		வெற்று,
		24,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		வெற்று,
		25,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		வெற்று,
		26,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		வெற்று,
		27,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		வெற்று,
		28,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		வெற்று,
		29,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_RSA,
		வெற்று,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		33,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_REVOKE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_ED25519,
		வெற்று,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		வெற்று,
		34,
		HKF_STATUS_OK,
		0,
		வெற்று,
		MRK_CA,
		"prometheus.example.com",
		வெற்று,
		சாவி_ECDSA,
		வெற்று,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, 0, 0, 0, -1, {
		வெற்று,
		37,
		HKF_STATUS_INVALID,
		0,
		வெற்று,
		MRK_ERROR,
		வெற்று,
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		38,
		HKF_STATUS_INVALID,
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		வெற்று,
		39,
		HKF_STATUS_INVALID,
		0,
		வெற்று,
		MRK_NONE,
		"prometheus.example.com",
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, HKF_STATUS_OK, சாவி_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,
		வெற்று,
		0,
	} },
	{ வெற்று, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		வெற்று,
		41,
		HKF_STATUS_INVALID,
		0,
		வெற்று,
		MRK_NONE,
		"sisyphus.example.com",
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,	/* filled at runtime */
		வெற்று,
		0,
	} },
	{ வெற்று, HKF_STATUS_OK, சாவி_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		வெற்று,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		வெற்று,
		MRK_NONE,
		"prometheus.example.com",
		வெற்று,
		சாவி_UNSPEC,
		வெற்று,	/* filled at runtime */
		வெற்று,
		0,
	} },
};

வெறுமை test_iterate(வெறுமை);

வெறுமை
test_iterate(வெறுமை)
{
	கட்டமைப்பு cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_PARSE_சாவி;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, வெற்று, வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, வெற்று, வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", வெற்று, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
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
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_PARSE_சாவி;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, அளவு(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = அளவு(expected_full)/அளவு(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_சாவி;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

