/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "hostfile.h"

ഘടന expected {
	സ്ഥിരം അക്ഷരം *താക്കോൽ_file;		/* Path for key, NULL for none */
	പൂർണ്ണസംഖ്യ no_parse_status;		/* Expected status w/o key parsing */
	പൂർണ്ണസംഖ്യ no_parse_keytype;		/* Expected keytype w/o key parsing */
	പൂർണ്ണസംഖ്യ match_host_p;		/* Match 'prometheus.example.com' */
	പൂർണ്ണസംഖ്യ match_host_s;		/* Match 'sisyphus.example.com' */
	പൂർണ്ണസംഖ്യ match_ipv4;			/* Match '192.0.2.1' */
	പൂർണ്ണസംഖ്യ match_ipv6;			/* Match '2001:db8::1' */
	പൂർണ്ണസംഖ്യ match_flags;		/* Expected flags from match */
	ഘടന hostkey_foreach_വരി l;	/* Expected line contents */
};

ഘടന cbctx {
	സ്ഥിരം ഘടന expected *expected;
	size_t nexpected;
	size_t i;
	പൂർണ്ണസംഖ്യ flags;
	പൂർണ്ണസംഖ്യ match_host_p;
	പൂർണ്ണസംഖ്യ match_host_s;
	പൂർണ്ണസംഖ്യ match_ipv4;
	പൂർണ്ണസംഖ്യ match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *_ctx)
{
	ഘടന cbctx *ctx = (ഘടന cbctx *)_ctx;
	സ്ഥിരം ഘടന expected *expected;
	പൂർണ്ണസംഖ്യ parse_താക്കോൽ = (ctx->flags & HKF_WANT_PARSE_താക്കോൽ) != 0;
	സ്ഥിരം പൂർണ്ണസംഖ്യ matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	പൂർണ്ണസംഖ്യ expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	വേണ്ടി (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		എങ്കിൽ (!matching)
			നിർത്തുക;
		എങ്കിൽ (ctx->match_host_p && expected->match_host_p)
			നിർത്തുക;
		എങ്കിൽ (ctx->match_host_s && expected->match_host_s)
			നിർത്തുക;
		എങ്കിൽ (ctx->match_ipv4 && expected->match_ipv4)
			നിർത്തുക;
		എങ്കിൽ (ctx->match_ipv6 && expected->match_ipv6)
			നിർത്തുക;
	}
	expected_status = (parse_താക്കോൽ || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) ചെയ്യുക { \
		എങ്കിൽ (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			എങ്കിൽ (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} ആകുമ്പോൾ (0)
	expected_keytype = (parse_താക്കോൽ || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	എങ്കിൽ (expected->l.keytype == താക്കോൽ_RSA ||
	    expected->no_parse_keytype == താക്കോൽ_RSA ||
	    expected->l.keytype == താക്കോൽ_ECDSA ||
	    expected->no_parse_keytype == താക്കോൽ_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	എങ്കിൽ (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = താക്കോൽ_UNSPEC;
		parse_താക്കോൽ = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, ശൂന്യ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	എങ്കിൽ (expected->l.വരി != ശൂന്യ)
		ASSERT_STRING_EQ(l->വരി, expected->l.വരി);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	എങ്കിൽ (expected->l.hosts != ശൂന്യ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	എങ്കിൽ (expected->l.rawkey != ശൂന്യ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	എങ്കിൽ (parse_താക്കോൽ) {
		എങ്കിൽ (expected->l.താക്കോൽ == ശൂന്യ)
			ASSERT_PTR_EQ(l->താക്കോൽ, ശൂന്യ);
		എങ്കിൽ (expected->l.താക്കോൽ != ശൂന്യ) {
			ASSERT_PTR_NE(l->താക്കോൽ, ശൂന്യ);
			ASSERT_INT_EQ(sshkey_equal(l->താക്കോൽ, expected->l.താക്കോൽ), 1);
		}
	}
	എങ്കിൽ (parse_താക്കോൽ && l->comment != ശൂന്യ && expected->l.comment != ശൂന്യ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	തിരികെ 0;
}

/* Loads public keys for a set of expected results */
സ്ഥിതം ശൂന്യം
prepare_expected(ഘടന expected *expected, size_t n)
{
	size_t i;

	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ (expected[i].താക്കോൽ_file == ശൂന്യ)
			തുടരുക;
#ifndef WITH_OPENSSL
		തിരഞ്ഞെടുപ്പ് (expected[i].l.keytype) {
		അവസ്ഥ താക്കോൽ_RSA:
		അവസ്ഥ താക്കോൽ_ECDSA:
			തുടരുക;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].താക്കോൽ_file), &expected[i].l.താക്കോൽ,
		    ശൂന്യ), 0);
	}
}

സ്ഥിതം ശൂന്യം
cleanup_expected(ഘടന expected *expected, size_t n)
{
	size_t i;

	വേണ്ടി (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.താക്കോൽ);
		expected[i].l.താക്കോൽ = ശൂന്യ;
	}
}

ഘടന expected expected_full[] = {
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ശൂന്യ,				/* hosts text */
		ശൂന്യ,				/* raw key, optional */
		താക്കോൽ_UNSPEC,			/* key type */
		ശൂന്യ,				/* deserialised key */
		ശൂന്യ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		2,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		3,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		4,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		7,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		8,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		9,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		12,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		13,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ശൂന്യ,
		14,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ശൂന്യ,
		17,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ശൂന്യ,
		18,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ശൂന്യ,
		19,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ശൂന്യ,
		21,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ശൂന്യ,
		22,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ശൂന്യ,
		23,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ശൂന്യ,
		24,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ശൂന്യ,
		25,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ശൂന്യ,
		26,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ശൂന്യ,
		27,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ശൂന്യ,
		28,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ശൂന്യ,
		29,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_RSA,
		ശൂന്യ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		33,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_REVOKE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_ED25519,
		ശൂന്യ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ശൂന്യ,
		34,
		HKF_STATUS_OK,
		0,
		ശൂന്യ,
		MRK_CA,
		"prometheus.example.com",
		ശൂന്യ,
		താക്കോൽ_ECDSA,
		ശൂന്യ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, 0, 0, 0, -1, {
		ശൂന്യ,
		37,
		HKF_STATUS_INVALID,
		0,
		ശൂന്യ,
		MRK_ERROR,
		ശൂന്യ,
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		38,
		HKF_STATUS_INVALID,
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ശൂന്യ,
		39,
		HKF_STATUS_INVALID,
		0,
		ശൂന്യ,
		MRK_NONE,
		"prometheus.example.com",
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, HKF_STATUS_OK, താക്കോൽ_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ശൂന്യ,
		41,
		HKF_STATUS_INVALID,
		0,
		ശൂന്യ,
		MRK_NONE,
		"sisyphus.example.com",
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,	/* filled at runtime */
		ശൂന്യ,
		0,
	} },
	{ ശൂന്യ, HKF_STATUS_OK, താക്കോൽ_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ശൂന്യ,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ശൂന്യ,
		MRK_NONE,
		"prometheus.example.com",
		ശൂന്യ,
		താക്കോൽ_UNSPEC,
		ശൂന്യ,	/* filled at runtime */
		ശൂന്യ,
		0,
	} },
};

ശൂന്യം test_iterate(ശൂന്യം);

ശൂന്യം
test_iterate(ശൂന്യം)
{
	ഘടന cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_PARSE_താക്കോൽ;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ശൂന്യ, ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ശൂന്യ, ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ശൂന്യ, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
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
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_PARSE_താക്കോൽ;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, വലുപ്പം(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = വലുപ്പം(expected_full)/വലുപ്പം(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_താക്കോൽ;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

