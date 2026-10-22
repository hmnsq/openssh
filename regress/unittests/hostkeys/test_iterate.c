/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"

ਬਣਤਰ expected {
	ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ_file;		/* Path for key, NULL for none */
	ਪੂਰਨ no_parse_ਸਥਿਤੀ;		/* Expected status w/o key parsing */
	ਪੂਰਨ no_parse_keytype;		/* Expected keytype w/o key parsing */
	ਪੂਰਨ ਮੇਲ_host_p;		/* Match 'prometheus.example.com' */
	ਪੂਰਨ ਮੇਲ_host_s;		/* Match 'sisyphus.example.com' */
	ਪੂਰਨ ਮੇਲ_ipv4;			/* Match '192.0.2.1' */
	ਪੂਰਨ ਮੇਲ_ipv6;			/* Match '2001:db8::1' */
	ਪੂਰਨ ਮੇਲ_flags;		/* Expected flags from match */
	ਬਣਤਰ hostkey_foreach_ਸਤਰ l;	/* Expected line contents */
};

ਬਣਤਰ cbctx {
	ਅਚਲ ਬਣਤਰ expected *expected;
	ਮਾਪ_t nexpected;
	ਮਾਪ_t i;
	ਪੂਰਨ flags;
	ਪੂਰਨ ਮੇਲ_host_p;
	ਪੂਰਨ ਮੇਲ_host_s;
	ਪੂਰਨ ਮੇਲ_ipv4;
	ਪੂਰਨ ਮੇਲ_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ਸਥਿਰ ਪੂਰਨ
check(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *_ctx)
{
	ਬਣਤਰ cbctx *ctx = (ਬਣਤਰ cbctx *)_ctx;
	ਅਚਲ ਬਣਤਰ expected *expected;
	ਪੂਰਨ parse_ਕੁੰਜੀ = (ctx->flags & HKF_WANT_PARSE_ਕੁੰਜੀ) != 0;
	ਅਚਲ ਪੂਰਨ matching = (ctx->flags & HKF_WANT_ਮੇਲ) != 0;
	u_int expected_ਸਥਿਤੀ, expected_ਮੇਲ;
	ਪੂਰਨ expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	ਲਈ (;;) {
		ASSERT_ਮਾਪ_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		ਜੇ (!matching)
			ਰੋਕੋ;
		ਜੇ (ctx->ਮੇਲ_host_p && expected->ਮੇਲ_host_p)
			ਰੋਕੋ;
		ਜੇ (ctx->ਮੇਲ_host_s && expected->ਮੇਲ_host_s)
			ਰੋਕੋ;
		ਜੇ (ctx->ਮੇਲ_ipv4 && expected->ਮੇਲ_ipv4)
			ਰੋਕੋ;
		ਜੇ (ctx->ਮੇਲ_ipv6 && expected->ਮੇਲ_ipv6)
			ਰੋਕੋ;
	}
	expected_ਸਥਿਤੀ = (parse_ਕੁੰਜੀ || expected->no_parse_ਸਥਿਤੀ < 0) ?
	    expected->l.ਸਥਿਤੀ : (u_int)expected->no_parse_ਸਥਿਤੀ;
	expected_ਮੇਲ = expected->l.ਮੇਲ;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UPDATE_ਮੇਲ_ਸਥਿਤੀ(x) ਕਰੋ { \
		ਜੇ (ctx->x && expected->x) { \
			expected_ਮੇਲ |= expected->x; \
			ਜੇ (expected_ਸਥਿਤੀ == HKF_ਸਥਿਤੀ_OK) \
				expected_ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_MATCHED; \
		} \
	} ਜਦੋਂ (0)
	expected_keytype = (parse_ਕੁੰਜੀ || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਜੇ (expected->l.keytype == ਕੁੰਜੀ_RSA ||
	    expected->no_parse_keytype == ਕੁੰਜੀ_RSA ||
	    expected->l.keytype == ਕੁੰਜੀ_ECDSA ||
	    expected->no_parse_keytype == ਕੁੰਜੀ_ECDSA)
		skip = 1;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਜੇ (skip) {
		expected_ਸਥਿਤੀ = HKF_ਸਥਿਤੀ_INVALID;
		expected_keytype = ਕੁੰਜੀ_UNSPEC;
		parse_ਕੁੰਜੀ = 0;
	}
	UPDATE_ਮੇਲ_ਸਥਿਤੀ(ਮੇਲ_host_p);
	UPDATE_ਮੇਲ_ਸਥਿਤੀ(ਮੇਲ_host_s);
	UPDATE_ਮੇਲ_ਸਥਿਤੀ(ਮੇਲ_ipv4);
	UPDATE_ਮੇਲ_ਸਥਿਤੀ(ਮੇਲ_ipv6);

	ASSERT_PTR_NE(l->ਰਸਤਾ, ਨਿਰਾ); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->ਸਥਿਤੀ, expected_ਸਥਿਤੀ);
	ASSERT_U_INT_EQ(l->ਮੇਲ, expected_ਮੇਲ);
	/* Not all test entries contain fulltext */
	ਜੇ (expected->l.ਸਤਰ != ਨਿਰਾ)
		ASSERT_STRING_EQ(l->ਸਤਰ, expected->l.ਸਤਰ);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	ਜੇ (expected->l.hosts != ਨਿਰਾ)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	ਜੇ (expected->l.rawkey != ਨਿਰਾ)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	ਜੇ (parse_ਕੁੰਜੀ) {
		ਜੇ (expected->l.ਕੁੰਜੀ == ਨਿਰਾ)
			ASSERT_PTR_EQ(l->ਕੁੰਜੀ, ਨਿਰਾ);
		ਜੇ (expected->l.ਕੁੰਜੀ != ਨਿਰਾ) {
			ASSERT_PTR_NE(l->ਕੁੰਜੀ, ਨਿਰਾ);
			ASSERT_INT_EQ(sshkey_equal(l->ਕੁੰਜੀ, expected->l.ਕੁੰਜੀ), 1);
		}
	}
	ਜੇ (parse_ਕੁੰਜੀ && l->comment != ਨਿਰਾ && expected->l.comment != ਨਿਰਾ)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	ਵਾਪਸ 0;
}

/* Loads public keys for a set of expected results */
ਸਥਿਰ ਖਾਲੀ
prepare_expected(ਬਣਤਰ expected *expected, ਮਾਪ_t n)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < n; i++) {
		ਜੇ (expected[i].ਕੁੰਜੀ_file == ਨਿਰਾ)
			ਜਾਰੀ;
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ਚੋਣ (expected[i].l.keytype) {
		ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
			ਜਾਰੀ;
		}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_ਲੱਦੋ_ਜਨਤਕ(
		    test_ਅੰਕੜੇ_file(expected[i].ਕੁੰਜੀ_file), &expected[i].l.ਕੁੰਜੀ,
		    ਨਿਰਾ), 0);
	}
}

ਸਥਿਰ ਖਾਲੀ
cleanup_expected(ਬਣਤਰ expected *expected, ਮਾਪ_t n)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.ਕੁੰਜੀ);
		expected[i].l.ਕੁੰਜੀ = ਨਿਰਾ;
	}
}

ਬਣਤਰ expected expected_ਭਰਿਆ[] = {
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,				/* path, don't care */
		1,				/* line number */
		HKF_ਸਥਿਤੀ_COMMENT,		/*ਸਥਿਤੀ*/
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ਨਿਰਾ,				/* hosts text */
		ਨਿਰਾ,				/* raw key, optional */
		ਕੁੰਜੀ_UNSPEC,			/* key type */
		ਨਿਰਾ,				/* deserialised key */
		ਨਿਰਾ,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		2,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		3,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		4,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		5,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		6,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_ਮੇਲ_HOST, 0, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		7,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_ਮੇਲ_HOST, 0, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		8,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_ਮੇਲ_HOST, 0, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		9,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		10,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		11,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		12,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		13,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_HOST, HKF_ਮੇਲ_IP, HKF_ਮੇਲ_IP, -1, {
		ਨਿਰਾ,
		14,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		15,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		16,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, -1, {
		ਨਿਰਾ,
		17,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, -1, {
		ਨਿਰਾ,
		18,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, -1, {
		ਨਿਰਾ,
		19,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		20,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, 0, -1, {
		ਨਿਰਾ,
		21,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, 0, -1, {
		ਨਿਰਾ,
		22,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, -1, {
		ਨਿਰਾ,
		23,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, 0, -1, {
		ਨਿਰਾ,
		24,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, 0, -1, {
		ਨਿਰਾ,
		25,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, -1, {
		ਨਿਰਾ,
		26,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_ਮੇਲ_HOST|HKF_ਮੇਲ_HOST_HASHED, 0, 0, 0, -1, {
		ਨਿਰਾ,
		27,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, 0, -1, {
		ਨਿਰਾ,
		28,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_ਮੇਲ_IP|HKF_ਮੇਲ_IP_HASHED, -1, {
		ਨਿਰਾ,
		29,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_RSA,
		ਨਿਰਾ,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		30,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		31,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		32,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		33,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_REVOKE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ED25519,
		ਨਿਰਾ,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_ਮੇਲ_HOST, 0, 0, 0, -1, {
		ਨਿਰਾ,
		34,
		HKF_ਸਥਿਤੀ_OK,
		0,
		ਨਿਰਾ,
		MRK_CA,
		"prometheus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_ECDSA,
		ਨਿਰਾ,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		35,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		36,
		HKF_ਸਥਿਤੀ_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, 0, 0, 0, -1, {
		ਨਿਰਾ,
		37,
		HKF_ਸਥਿਤੀ_INVALID,
		0,
		ਨਿਰਾ,
		MRK_ERROR,
		ਨਿਰਾ,
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		38,
		HKF_ਸਥਿਤੀ_INVALID,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, HKF_ਮੇਲ_HOST, 0, 0, 0, -1, {
		ਨਿਰਾ,
		39,
		HKF_ਸਥਿਤੀ_INVALID,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"prometheus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, HKF_ਸਥਿਤੀ_OK, ਕੁੰਜੀ_ED25519, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		40,
		HKF_ਸਥਿਤੀ_INVALID,	/* Would be ok if key not parsed */
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, -1, -1, 0, HKF_ਮੇਲ_HOST, 0, 0, -1, {
		ਨਿਰਾ,
		41,
		HKF_ਸਥਿਤੀ_INVALID,
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"sisyphus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,	/* filled at runtime */
		ਨਿਰਾ,
		0,
	} },
	{ ਨਿਰਾ, HKF_ਸਥਿਤੀ_OK, ਕੁੰਜੀ_RSA, HKF_ਮੇਲ_HOST, 0, 0, 0, -1, {
		ਨਿਰਾ,
		42,
		HKF_ਸਥਿਤੀ_INVALID,	/* Would be ok if key not parsed */
		0,
		ਨਿਰਾ,
		MRK_NONE,
		"prometheus.example.com",
		ਨਿਰਾ,
		ਕੁੰਜੀ_UNSPEC,
		ਨਿਰਾ,	/* filled at runtime */
		ਨਿਰਾ,
		0,
	} },
};

ਖਾਲੀ test_iterate(ਖਾਲੀ);

ਖਾਲੀ
test_iterate(ਖਾਲੀ)
{
	ਬਣਤਰ cbctx ctx;

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate all with key parse");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_PARSE_ਕੁੰਜੀ;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, ਨਿਰਾ, ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate all without key parse");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, ਨਿਰਾ, ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify host 1");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	ctx.ਮੇਲ_host_p = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify host 2");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	ctx.ਮੇਲ_host_s = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match host 1");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	ctx.ਮੇਲ_host_p = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match host 2");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	ctx.ਮੇਲ_host_s = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify host missing");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match host missing");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ਨਿਰਾ, ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	ctx.ਮੇਲ_ipv4 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	ctx.ਮੇਲ_ipv6 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match IPv4");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	ctx.ਮੇਲ_ipv4 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match IPv6");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	ctx.ਮੇਲ_ipv6 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match addr missing");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = 0;
	ctx.ਮੇਲ_host_s = 1;
	ctx.ਮੇਲ_ipv4 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ;
	ctx.ਮੇਲ_host_p = 1;
	ctx.ਮੇਲ_ipv6 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_PARSE_ਕੁੰਜੀ;
	ctx.ਮੇਲ_host_s = 1;
	ctx.ਮੇਲ_ipv4 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, ਆਕਾਰ(ctx));
	ctx.expected = expected_ਭਰਿਆ;
	ctx.nexpected = ਆਕਾਰ(expected_ਭਰਿਆ)/ਆਕਾਰ(*expected_ਭਰਿਆ);
	ctx.flags = HKF_WANT_ਮੇਲ|HKF_WANT_PARSE_ਕੁੰਜੀ;
	ctx.ਮੇਲ_host_p = 1;
	ctx.ਮੇਲ_ipv6 = 1;
	prepare_expected(expected_ਭਰਿਆ, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ਅੰਕੜੇ_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_ਭਰਿਆ, ctx.nexpected);
	TEST_ਪੂਰਾ();
}

