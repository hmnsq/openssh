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

ರಚನೆ expected {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ_file;		/* Path for key, NULL for none */
	ಪೂರ್ಣಾಂಕ no_parse_ಸ್ಥಿತಿ;		/* Expected status w/o key parsing */
	ಪೂರ್ಣಾಂಕ no_parse_keytype;		/* Expected keytype w/o key parsing */
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_host_p;		/* Match 'prometheus.example.com' */
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_host_s;		/* Match 'sisyphus.example.com' */
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_ipv4;			/* Match '192.0.2.1' */
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_ipv6;			/* Match '2001:db8::1' */
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_flags;		/* Expected flags from match */
	ರಚನೆ hostkey_foreach_ಸಾಲು l;	/* Expected line contents */
};

ರಚನೆ cbctx {
	ಸ್ಥಿರಾಂಕ ರಚನೆ expected *expected;
	ಗಾತ್ರ_t nexpected;
	ಗಾತ್ರ_t i;
	ಪೂರ್ಣಾಂಕ flags;
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_host_p;
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_host_s;
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_ipv4;
	ಪೂರ್ಣಾಂಕ ಹೊಂದಿಕೆ_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *_ctx)
{
	ರಚನೆ cbctx *ctx = (ರಚನೆ cbctx *)_ctx;
	ಸ್ಥಿರಾಂಕ ರಚನೆ expected *expected;
	ಪೂರ್ಣಾಂಕ parse_ಕೀಲಿ = (ctx->flags & HKF_WANT_PARSE_ಕೀಲಿ) != 0;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ matching = (ctx->flags & HKF_WANT_ಹೊಂದಿಕೆ) != 0;
	u_int expected_ಸ್ಥಿತಿ, expected_ಹೊಂದಿಕೆ;
	ಪೂರ್ಣಾಂಕ expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	ಗಾಗಿ (;;) {
		ASSERT_ಗಾತ್ರ_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		ಆದರೆ (!matching)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (ctx->ಹೊಂದಿಕೆ_host_p && expected->ಹೊಂದಿಕೆ_host_p)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (ctx->ಹೊಂದಿಕೆ_host_s && expected->ಹೊಂದಿಕೆ_host_s)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (ctx->ಹೊಂದಿಕೆ_ipv4 && expected->ಹೊಂದಿಕೆ_ipv4)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (ctx->ಹೊಂದಿಕೆ_ipv6 && expected->ಹೊಂದಿಕೆ_ipv6)
			ನಿಲ್ಲಿಸು;
	}
	expected_ಸ್ಥಿತಿ = (parse_ಕೀಲಿ || expected->no_parse_ಸ್ಥಿತಿ < 0) ?
	    expected->l.ಸ್ಥಿತಿ_2 : (u_int)expected->no_parse_ಸ್ಥಿತಿ;
	expected_ಹೊಂದಿಕೆ = expected->l.ಹೊಂದಿಕೆ;
#ವ್ಯಾಖ್ಯಾನಿಸು UPDATE_ಹೊಂದಿಕೆ_ಸ್ಥಿತಿ(x) ಮಾಡು { \
		ಆದರೆ (ctx->x && expected->x) { \
			expected_ಹೊಂದಿಕೆ |= expected->x; \
			ಆದರೆ (expected_ಸ್ಥಿತಿ == HKF_ಸ್ಥಿತಿ_OK) \
				expected_ಸ್ಥಿತಿ = HKF_ಸ್ಥಿತಿ_MATCHED; \
		} \
	} ಆಗ (0)
	expected_keytype = (parse_ಕೀಲಿ || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
	ಆದರೆ (expected->l.keytype == ಕೀಲಿ_RSA ||
	    expected->no_parse_keytype == ಕೀಲಿ_RSA ||
	    expected->l.keytype == ಕೀಲಿ_ECDSA ||
	    expected->no_parse_keytype == ಕೀಲಿ_ECDSA)
		skip = 1;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಆದರೆ (skip) {
		expected_ಸ್ಥಿತಿ = HKF_ಸ್ಥಿತಿ_INVALID;
		expected_keytype = ಕೀಲಿ_UNSPEC;
		parse_ಕೀಲಿ = 0;
	}
	UPDATE_ಹೊಂದಿಕೆ_ಸ್ಥಿತಿ(ಹೊಂದಿಕೆ_host_p);
	UPDATE_ಹೊಂದಿಕೆ_ಸ್ಥಿತಿ(ಹೊಂದಿಕೆ_host_s);
	UPDATE_ಹೊಂದಿಕೆ_ಸ್ಥಿತಿ(ಹೊಂದಿಕೆ_ipv4);
	UPDATE_ಹೊಂದಿಕೆ_ಸ್ಥಿತಿ(ಹೊಂದಿಕೆ_ipv6);

	ASSERT_PTR_NE(l->ಮಾರ್ಗ, ಖಾಲಿ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->ಸ್ಥಿತಿ_2, expected_ಸ್ಥಿತಿ);
	ASSERT_U_INT_EQ(l->ಹೊಂದಿಕೆ, expected_ಹೊಂದಿಕೆ);
	/* Not all test entries contain fulltext */
	ಆದರೆ (expected->l.ಸಾಲು != ಖಾಲಿ)
		ASSERT_STRING_EQ(l->ಸಾಲು, expected->l.ಸಾಲು);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	ಆದರೆ (expected->l.hosts != ಖಾಲಿ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	ಆದರೆ (expected->l.rawkey != ಖಾಲಿ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	ಆದರೆ (parse_ಕೀಲಿ) {
		ಆದರೆ (expected->l.ಕೀಲಿ == ಖಾಲಿ)
			ASSERT_PTR_EQ(l->ಕೀಲಿ, ಖಾಲಿ);
		ಆದರೆ (expected->l.ಕೀಲಿ != ಖಾಲಿ) {
			ASSERT_PTR_NE(l->ಕೀಲಿ, ಖಾಲಿ);
			ASSERT_INT_EQ(sshkey_equal(l->ಕೀಲಿ, expected->l.ಕೀಲಿ), 1);
		}
	}
	ಆದರೆ (parse_ಕೀಲಿ && l->comment != ಖಾಲಿ && expected->l.comment != ಖಾಲಿ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	ಹಿಂತಿರುಗಿ 0;
}

/* Loads public keys for a set of expected results */
ಸ್ಥಿರ ಶೂನ್ಯ
prepare_expected(ರಚನೆ expected *expected, ಗಾತ್ರ_t n)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < n; i++) {
		ಆದರೆ (expected[i].ಕೀಲಿ_file == ಖಾಲಿ)
			ಮುಂದುವರಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL
		ಆಯ್ಕೆ (expected[i].l.keytype) {
		ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
			ಮುಂದುವರಿ;
		}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_ತುಂಬು_ಬಹಿರಂಗ(
		    test_ದತ್ತಾಂಶ_file(expected[i].ಕೀಲಿ_file), &expected[i].l.ಕೀಲಿ,
		    ಖಾಲಿ), 0);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_expected(ರಚನೆ expected *expected, ಗಾತ್ರ_t n)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.ಕೀಲಿ);
		expected[i].l.ಕೀಲಿ = ಖಾಲಿ;
	}
}

ರಚನೆ expected expected_ತುಂಬಿದ[] = {
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,				/* path, don't care */
		1,				/* line number */
		HKF_ಸ್ಥಿತಿ_COMMENT,		/*ಸ್ಥಿತಿ*/
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ಖಾಲಿ,				/* hosts text */
		ಖಾಲಿ,				/* raw key, optional */
		ಕೀಲಿ_UNSPEC,			/* key type */
		ಖಾಲಿ,				/* deserialised key */
		ಖಾಲಿ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		2,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		3,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		4,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		5,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		6,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, 0, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		7,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, 0, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		8,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, 0, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		9,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		10,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		11,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		12,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		13,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_HOST, HKF_ಹೊಂದಿಕೆ_IP, HKF_ಹೊಂದಿಕೆ_IP, -1, {
		ಖಾಲಿ,
		14,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		15,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		16,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, -1, {
		ಖಾಲಿ,
		17,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, -1, {
		ಖಾಲಿ,
		18,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, -1, {
		ಖಾಲಿ,
		19,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		20,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, 0, -1, {
		ಖಾಲಿ,
		21,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, 0, -1, {
		ಖಾಲಿ,
		22,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, -1, {
		ಖಾಲಿ,
		23,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, 0, -1, {
		ಖಾಲಿ,
		24,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, 0, -1, {
		ಖಾಲಿ,
		25,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, -1, {
		ಖಾಲಿ,
		26,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST|HKF_ಹೊಂದಿಕೆ_HOST_HASHED, 0, 0, 0, -1, {
		ಖಾಲಿ,
		27,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, 0, -1, {
		ಖಾಲಿ,
		28,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_ಹೊಂದಿಕೆ_IP|HKF_ಹೊಂದಿಕೆ_IP_HASHED, -1, {
		ಖಾಲಿ,
		29,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_RSA,
		ಖಾಲಿ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		30,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		31,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		32,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		33,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_REVOKE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_ED25519,
		ಖಾಲಿ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, 0, -1, {
		ಖಾಲಿ,
		34,
		HKF_ಸ್ಥಿತಿ_OK,
		0,
		ಖಾಲಿ,
		MRK_CA,
		"prometheus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_ECDSA,
		ಖಾಲಿ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		35,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		36,
		HKF_ಸ್ಥಿತಿ_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, 0, 0, 0, -1, {
		ಖಾಲಿ,
		37,
		HKF_ಸ್ಥಿತಿ_INVALID,
		0,
		ಖಾಲಿ,
		MRK_ERROR,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		38,
		HKF_ಸ್ಥಿತಿ_INVALID,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, 0, -1, {
		ಖಾಲಿ,
		39,
		HKF_ಸ್ಥಿತಿ_INVALID,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"prometheus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, HKF_ಸ್ಥಿತಿ_OK, ಕೀಲಿ_ED25519, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		40,
		HKF_ಸ್ಥಿತಿ_INVALID,	/* Would be ok if key not parsed */
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, -1, -1, 0, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, -1, {
		ಖಾಲಿ,
		41,
		HKF_ಸ್ಥಿತಿ_INVALID,
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"sisyphus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,	/* filled at runtime */
		ಖಾಲಿ,
		0,
	} },
	{ ಖಾಲಿ, HKF_ಸ್ಥಿತಿ_OK, ಕೀಲಿ_RSA, HKF_ಹೊಂದಿಕೆ_HOST, 0, 0, 0, -1, {
		ಖಾಲಿ,
		42,
		HKF_ಸ್ಥಿತಿ_INVALID,	/* Would be ok if key not parsed */
		0,
		ಖಾಲಿ,
		MRK_NONE,
		"prometheus.example.com",
		ಖಾಲಿ,
		ಕೀಲಿ_UNSPEC,
		ಖಾಲಿ,	/* filled at runtime */
		ಖಾಲಿ,
		0,
	} },
};

ಶೂನ್ಯ test_iterate(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_iterate(ಶೂನ್ಯ)
{
	ರಚನೆ cbctx ctx;

	TEST_ಆರಂಭ("hostkeys_iterate all with key parse");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_PARSE_ಕೀಲಿ;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, ಖಾಲಿ, ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate all without key parse");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, ಖಾಲಿ, ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify host 1");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	ctx.ಹೊಂದಿಕೆ_host_p = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify host 2");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	ctx.ಹೊಂದಿಕೆ_host_s = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match host 1");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	ctx.ಹೊಂದಿಕೆ_host_p = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match host 2");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	ctx.ಹೊಂದಿಕೆ_host_s = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify host missing");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match host missing");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ಖಾಲಿ, ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	ctx.ಹೊಂದಿಕೆ_ipv4 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	ctx.ಹೊಂದಿಕೆ_ipv6 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match IPv4");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	ctx.ಹೊಂದಿಕೆ_ipv4 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match IPv6");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	ctx.ಹೊಂದಿಕೆ_ipv6 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match addr missing");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = 0;
	ctx.ಹೊಂದಿಕೆ_host_s = 1;
	ctx.ಹೊಂದಿಕೆ_ipv4 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ;
	ctx.ಹೊಂದಿಕೆ_host_p = 1;
	ctx.ಹೊಂದಿಕೆ_ipv6 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_PARSE_ಕೀಲಿ;
	ctx.ಹೊಂದಿಕೆ_host_s = 1;
	ctx.ಹೊಂದಿಕೆ_ipv4 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, ಗಾತ್ರ(ctx));
	ctx.expected = expected_ತುಂಬಿದ;
	ctx.nexpected = ಗಾತ್ರ(expected_ತುಂಬಿದ)/ಗಾತ್ರ(*expected_ತುಂಬಿದ);
	ctx.flags = HKF_WANT_ಹೊಂದಿಕೆ|HKF_WANT_PARSE_ಕೀಲಿ;
	ctx.ಹೊಂದಿಕೆ_host_p = 1;
	ctx.ಹೊಂದಿಕೆ_ipv6 = 1;
	prepare_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ದತ್ತಾಂಶ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ತುಂಬಿದ, ctx.nexpected);
	TEST_ಮುಗಿದ();
}

