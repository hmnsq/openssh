/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "hostfile.h"

સંરચના expected {
	અચલ અક્ષર *ચાવી_file;		/* Path for key, NULL for none */
	પૂર્ણાંક no_parse_status;		/* Expected status w/o key parsing */
	પૂર્ણાંક no_parse_keytype;		/* Expected keytype w/o key parsing */
	પૂર્ણાંક match_host_p;		/* Match 'prometheus.example.com' */
	પૂર્ણાંક match_host_s;		/* Match 'sisyphus.example.com' */
	પૂર્ણાંક match_ipv4;			/* Match '192.0.2.1' */
	પૂર્ણાંક match_ipv6;			/* Match '2001:db8::1' */
	પૂર્ણાંક match_flags;		/* Expected flags from match */
	સંરચના hostkey_foreach_લીટી l;	/* Expected line contents */
};

સંરચના cbctx {
	અચલ સંરચના expected *expected;
	size_t nexpected;
	size_t i;
	પૂર્ણાંક flags;
	પૂર્ણાંક match_host_p;
	પૂર્ણાંક match_host_s;
	પૂર્ણાંક match_ipv4;
	પૂર્ણાંક match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
સ્થિર પૂર્ણાંક
check(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *_ctx)
{
	સંરચના cbctx *ctx = (સંરચના cbctx *)_ctx;
	અચલ સંરચના expected *expected;
	પૂર્ણાંક parse_ચાવી = (ctx->flags & HKF_WANT_PARSE_ચાવી) != 0;
	અચલ પૂર્ણાંક matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	પૂર્ણાંક expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	માટે (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		જો (!matching)
			તોડો;
		જો (ctx->match_host_p && expected->match_host_p)
			તોડો;
		જો (ctx->match_host_s && expected->match_host_s)
			તોડો;
		જો (ctx->match_ipv4 && expected->match_ipv4)
			તોડો;
		જો (ctx->match_ipv6 && expected->match_ipv6)
			તોડો;
	}
	expected_status = (parse_ચાવી || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) કરો { \
		જો (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			જો (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} જ્યારે (0)
	expected_keytype = (parse_ચાવી || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	જો (expected->l.keytype == ચાવી_RSA ||
	    expected->no_parse_keytype == ચાવી_RSA ||
	    expected->l.keytype == ચાવી_ECDSA ||
	    expected->no_parse_keytype == ચાવી_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	જો (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = ચાવી_UNSPEC;
		parse_ચાવી = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, ખાલી); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	જો (expected->l.લીટી != ખાલી)
		ASSERT_STRING_EQ(l->લીટી, expected->l.લીટી);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	જો (expected->l.hosts != ખાલી)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	જો (expected->l.rawkey != ખાલી)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	જો (parse_ચાવી) {
		જો (expected->l.ચાવી == ખાલી)
			ASSERT_PTR_EQ(l->ચાવી, ખાલી);
		જો (expected->l.ચાવી != ખાલી) {
			ASSERT_PTR_NE(l->ચાવી, ખાલી);
			ASSERT_INT_EQ(sshkey_equal(l->ચાવી, expected->l.ચાવી), 1);
		}
	}
	જો (parse_ચાવી && l->comment != ખાલી && expected->l.comment != ખાલી)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	પાછા 0;
}

/* Loads public keys for a set of expected results */
સ્થિર શૂન્ય
prepare_expected(સંરચના expected *expected, size_t n)
{
	size_t i;

	માટે (i = 0; i < n; i++) {
		જો (expected[i].ચાવી_file == ખાલી)
			ચાલુ;
#ifndef WITH_OPENSSL
		પસંદગી (expected[i].l.keytype) {
		સ્થિતિ ચાવી_RSA:
		સ્થિતિ ચાવી_ECDSA:
			ચાલુ;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].ચાવી_file), &expected[i].l.ચાવી,
		    ખાલી), 0);
	}
}

સ્થિર શૂન્ય
cleanup_expected(સંરચના expected *expected, size_t n)
{
	size_t i;

	માટે (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.ચાવી);
		expected[i].l.ચાવી = ખાલી;
	}
}

સંરચના expected expected_full[] = {
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ખાલી,				/* hosts text */
		ખાલી,				/* raw key, optional */
		ચાવી_UNSPEC,			/* key type */
		ખાલી,				/* deserialised key */
		ખાલી,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		2,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		3,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		4,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		7,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		8,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		9,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		12,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		13,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ખાલી,
		14,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ખાલી,
		17,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ખાલી,
		18,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ખાલી,
		19,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ખાલી,
		21,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ખાલી,
		22,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ખાલી,
		23,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ખાલી,
		24,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ખાલી,
		25,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ખાલી,
		26,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ખાલી,
		27,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ખાલી,
		28,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ખાલી,
		29,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_RSA,
		ખાલી,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		33,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_REVOKE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_ED25519,
		ખાલી,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ખાલી,
		34,
		HKF_STATUS_OK,
		0,
		ખાલી,
		MRK_CA,
		"prometheus.example.com",
		ખાલી,
		ચાવી_ECDSA,
		ખાલી,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, 0, 0, 0, -1, {
		ખાલી,
		37,
		HKF_STATUS_INVALID,
		0,
		ખાલી,
		MRK_ERROR,
		ખાલી,
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		38,
		HKF_STATUS_INVALID,
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ખાલી,
		39,
		HKF_STATUS_INVALID,
		0,
		ખાલી,
		MRK_NONE,
		"prometheus.example.com",
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, HKF_STATUS_OK, ચાવી_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,
		ખાલી,
		0,
	} },
	{ ખાલી, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ખાલી,
		41,
		HKF_STATUS_INVALID,
		0,
		ખાલી,
		MRK_NONE,
		"sisyphus.example.com",
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,	/* filled at runtime */
		ખાલી,
		0,
	} },
	{ ખાલી, HKF_STATUS_OK, ચાવી_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ખાલી,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ખાલી,
		MRK_NONE,
		"prometheus.example.com",
		ખાલી,
		ચાવી_UNSPEC,
		ખાલી,	/* filled at runtime */
		ખાલી,
		0,
	} },
};

શૂન્ય test_iterate(શૂન્ય);

શૂન્ય
test_iterate(શૂન્ય)
{
	સંરચના cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ચાવી;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ખાલી, ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, ખાલી, ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ખાલી, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
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
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_PARSE_ચાવી;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, કદ(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = કદ(expected_full)/કદ(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_ચાવી;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

