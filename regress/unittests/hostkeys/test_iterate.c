/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"

ಸಂರಚನಾ expected {
	ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ_file;		/* Path for key, NULL for none */
	ಪೂರ್ಣಾಙ್ಕ no_parse_status;		/* Expected status w/o key parsing */
	ಪೂರ್ಣಾಙ್ಕ no_parse_keytype;		/* Expected keytype w/o key parsing */
	ಪೂರ್ಣಾಙ್ಕ match_host_p;		/* Match 'prometheus.example.com' */
	ಪೂರ್ಣಾಙ್ಕ match_host_s;		/* Match 'sisyphus.example.com' */
	ಪೂರ್ಣಾಙ್ಕ match_ipv4;			/* Match '192.0.2.1' */
	ಪೂರ್ಣಾಙ್ಕ match_ipv6;			/* Match '2001:db8::1' */
	ಪೂರ್ಣಾಙ್ಕ match_flags;		/* Expected flags from match */
	ಸಂರಚನಾ hostkey_foreach_ಸಾಲು l;	/* Expected line contents */
};

ಸಂರಚನಾ cbctx {
	ಧ್ರುವ ಸಂರಚನಾ expected *expected;
	size_t nexpected;
	size_t i;
	ಪೂರ್ಣಾಙ್ಕ flags;
	ಪೂರ್ಣಾಙ್ಕ match_host_p;
	ಪೂರ್ಣಾಙ್ಕ match_host_s;
	ಪೂರ್ಣಾಙ್ಕ match_ipv4;
	ಪೂರ್ಣಾಙ್ಕ match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ಸಂರಚನಾ cbctx *ctx = (ಸಂರಚನಾ cbctx *)_ctx;
	ಧ್ರುವ ಸಂರಚನಾ expected *expected;
	ಪೂರ್ಣಾಙ್ಕ parse_ಕೀಲಿ = (ctx->flags & HKF_WANT_PARSE_ಕೀಲಿ) != 0;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	ಪೂರ್ಣಾಙ್ಕ expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	ಪ್ರತಿ (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		ಯದಿ (!matching)
			ಭಙ್ಗ;
		ಯದಿ (ctx->match_host_p && expected->match_host_p)
			ಭಙ್ಗ;
		ಯದಿ (ctx->match_host_s && expected->match_host_s)
			ಭಙ್ಗ;
		ಯದಿ (ctx->match_ipv4 && expected->match_ipv4)
			ಭಙ್ಗ;
		ಯದಿ (ctx->match_ipv6 && expected->match_ipv6)
			ಭಙ್ಗ;
	}
	expected_status = (parse_ಕೀಲಿ || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) ಕುರು { \
		ಯದಿ (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			ಯದಿ (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} ಯಾವತ್ (0)
	expected_keytype = (parse_ಕೀಲಿ || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	ಯದಿ (expected->l.keytype == ಕೀಲಿ_RSA ||
	    expected->no_parse_keytype == ಕೀಲಿ_RSA ||
	    expected->l.keytype == ಕೀಲಿ_ECDSA ||
	    expected->no_parse_keytype == ಕೀಲಿ_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	ಯದಿ (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = ಕೀಲಿ_UNSPEC;
		parse_ಕೀಲಿ = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, ರಿಕ್ತ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	ಯದಿ (expected->l.ಸಾಲು != ರಿಕ್ತ)
		ASSERT_STRING_EQ(l->ಸಾಲು, expected->l.ಸಾಲು);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	ಯದಿ (expected->l.hosts != ರಿಕ್ತ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	ಯದಿ (expected->l.rawkey != ರಿಕ್ತ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	ಯದಿ (parse_ಕೀಲಿ) {
		ಯದಿ (expected->l.ಕೀಲಿ == ರಿಕ್ತ)
			ASSERT_PTR_EQ(l->ಕೀಲಿ, ರಿಕ್ತ);
		ಯದಿ (expected->l.ಕೀಲಿ != ರಿಕ್ತ) {
			ASSERT_PTR_NE(l->ಕೀಲಿ, ರಿಕ್ತ);
			ASSERT_INT_EQ(sshkey_equal(l->ಕೀಲಿ, expected->l.ಕೀಲಿ), 1);
		}
	}
	ಯದಿ (parse_ಕೀಲಿ && l->comment != ರಿಕ್ತ && expected->l.comment != ರಿಕ್ತ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Loads public keys for a set of expected results */
ಸ್ಥಿರ ಶೂನ್ಯ
prepare_expected(ಸಂರಚನಾ expected *expected, size_t n)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಯದಿ (expected[i].ಕೀಲಿ_file == ರಿಕ್ತ)
			ಅನುವರ್ತ;
#ifndef WITH_OPENSSL
		ವಿಕಲ್ಪ (expected[i].l.keytype) {
		ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಪಕ್ಷ ಕೀಲಿ_ECDSA:
			ಅನುವರ್ತ;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].ಕೀಲಿ_file), &expected[i].l.ಕೀಲಿ,
		    ರಿಕ್ತ), 0);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_expected(ಸಂರಚನಾ expected *expected, size_t n)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.ಕೀಲಿ);
		expected[i].l.ಕೀಲಿ = ರಿಕ್ತ;
	}
}

ಸಂರಚನಾ expected expected_full[] = {
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ರಿಕ್ತ,				/* hosts text */
		ರಿಕ್ತ,				/* raw key, optional */
		ಕೀಲಿ_UNSPEC,			/* key type */
		ರಿಕ್ತ,				/* deserialised key */
		ರಿಕ್ತ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		2,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		3,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		4,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		7,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		8,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		9,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		12,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		13,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ರಿಕ್ತ,
		14,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ರಿಕ್ತ,
		17,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ರಿಕ್ತ,
		18,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ರಿಕ್ತ,
		19,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		21,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ರಿಕ್ತ,
		22,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ರಿಕ್ತ,
		23,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		24,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ರಿಕ್ತ,
		25,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ರಿಕ್ತ,
		26,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		27,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ರಿಕ್ತ,
		28,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ರಿಕ್ತ,
		29,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_RSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		33,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_REVOKE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_ED25519,
		ರಿಕ್ತ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		34,
		HKF_STATUS_OK,
		0,
		ರಿಕ್ತ,
		MRK_CA,
		"prometheus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_ECDSA,
		ರಿಕ್ತ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		37,
		HKF_STATUS_INVALID,
		0,
		ರಿಕ್ತ,
		MRK_ERROR,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		38,
		HKF_STATUS_INVALID,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		39,
		HKF_STATUS_INVALID,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"prometheus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, HKF_STATUS_OK, ಕೀಲಿ_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ರಿಕ್ತ,
		41,
		HKF_STATUS_INVALID,
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"sisyphus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,	/* filled at runtime */
		ರಿಕ್ತ,
		0,
	} },
	{ ರಿಕ್ತ, HKF_STATUS_OK, ಕೀಲಿ_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ರಿಕ್ತ,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ರಿಕ್ತ,
		MRK_NONE,
		"prometheus.example.com",
		ರಿಕ್ತ,
		ಕೀಲಿ_UNSPEC,
		ರಿಕ್ತ,	/* filled at runtime */
		ರಿಕ್ತ,
		0,
	} },
};

ಶೂನ್ಯ test_iterate(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_iterate(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ಕೀಲಿ;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ರಿಕ್ತ, ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ರಿಕ್ತ, ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ರಿಕ್ತ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
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
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ಕೀಲಿ;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, ಪರಿಮಾಣ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = ಪರಿಮಾಣ(expected_full)/ಪರಿಮಾಣ(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_ಕೀಲಿ;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

