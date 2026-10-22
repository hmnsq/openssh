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

কাঠামো expected {
	ধ্রুবক অক্ষর *চাবি_file;		/* Path for key, NULL for none */
	পূর্ণসংখ্যা no_parse_status;		/* Expected status w/o key parsing */
	পূর্ণসংখ্যা no_parse_keytype;		/* Expected keytype w/o key parsing */
	পূর্ণসংখ্যা match_host_p;		/* Match 'prometheus.example.com' */
	পূর্ণসংখ্যা match_host_s;		/* Match 'sisyphus.example.com' */
	পূর্ণসংখ্যা match_ipv4;			/* Match '192.0.2.1' */
	পূর্ণসংখ্যা match_ipv6;			/* Match '2001:db8::1' */
	পূর্ণসংখ্যা match_flags;		/* Expected flags from match */
	কাঠামো hostkey_foreach_সারি l;	/* Expected line contents */
};

কাঠামো cbctx {
	ধ্রুবক কাঠামো expected *expected;
	আকার_t nexpected;
	আকার_t i;
	পূর্ণসংখ্যা flags;
	পূর্ণসংখ্যা match_host_p;
	পূর্ণসংখ্যা match_host_s;
	পূর্ণসংখ্যা match_ipv4;
	পূর্ণসংখ্যা match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
স্থির পূর্ণসংখ্যা
check(কাঠামো hostkey_foreach_সারি *l, শূন্য *_ctx)
{
	কাঠামো cbctx *ctx = (কাঠামো cbctx *)_ctx;
	ধ্রুবক কাঠামো expected *expected;
	পূর্ণসংখ্যা parse_চাবি = (ctx->flags & HKF_WANT_PARSE_চাবি) != 0;
	ধ্রুবক পূর্ণসংখ্যা matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	পূর্ণসংখ্যা expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	জন্য (;;) {
		ASSERT_আকার_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		যদি (!matching)
			বিরতি;
		যদি (ctx->match_host_p && expected->match_host_p)
			বিরতি;
		যদি (ctx->match_host_s && expected->match_host_s)
			বিরতি;
		যদি (ctx->match_ipv4 && expected->match_ipv4)
			বিরতি;
		যদি (ctx->match_ipv6 && expected->match_ipv6)
			বিরতি;
	}
	expected_status = (parse_চাবি || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) করো { \
		যদি (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			যদি (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} যখন (0)
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

	ASSERT_PTR_NE(l->path, ফাঁকা); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	যদি (expected->l.সারি != ফাঁকা)
		ASSERT_STRING_EQ(l->সারি, expected->l.সারি);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	যদি (expected->l.hosts != ফাঁকা)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	যদি (expected->l.rawkey != ফাঁকা)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	যদি (parse_চাবি) {
		যদি (expected->l.চাবি == ফাঁকা)
			ASSERT_PTR_EQ(l->চাবি, ফাঁকা);
		যদি (expected->l.চাবি != ফাঁকা) {
			ASSERT_PTR_NE(l->চাবি, ফাঁকা);
			ASSERT_INT_EQ(sshkey_equal(l->চাবি, expected->l.চাবি), 1);
		}
	}
	যদি (parse_চাবি && l->comment != ফাঁকা && expected->l.comment != ফাঁকা)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	ফেরত 0;
}

/* Loads public keys for a set of expected results */
স্থির শূন্য
prepare_expected(কাঠামো expected *expected, আকার_t n)
{
	আকার_t i;

	জন্য (i = 0; i < n; i++) {
		যদি (expected[i].চাবি_file == ফাঁকা)
			চালু;
#ifndef WITH_OPENSSL
		নির্বাচন (expected[i].l.keytype) {
		ক্ষেত্র চাবি_RSA:
		ক্ষেত্র চাবি_ECDSA:
			চালু;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_তথ্য_file(expected[i].চাবি_file), &expected[i].l.চাবি,
		    ফাঁকা), 0);
	}
}

স্থির শূন্য
cleanup_expected(কাঠামো expected *expected, আকার_t n)
{
	আকার_t i;

	জন্য (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.চাবি);
		expected[i].l.চাবি = ফাঁকা;
	}
}

কাঠামো expected expected_full[] = {
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		ফাঁকা,				/* hosts text */
		ফাঁকা,				/* raw key, optional */
		চাবি_UNSPEC,			/* key type */
		ফাঁকা,				/* deserialised key */
		ফাঁকা,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		2,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		3,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		4,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		7,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		8,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		9,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		12,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		13,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		ফাঁকা,
		14,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ফাঁকা,
		17,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ফাঁকা,
		18,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		ফাঁকা,
		19,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ফাঁকা,
		21,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ফাঁকা,
		22,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ফাঁকা,
		23,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ফাঁকা,
		24,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ফাঁকা,
		25,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ফাঁকা,
		26,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		ফাঁকা,
		27,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		ফাঁকা,
		28,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		ফাঁকা,
		29,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_RSA,
		ফাঁকা,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		33,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_REVOKE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_ED25519,
		ফাঁকা,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ফাঁকা,
		34,
		HKF_STATUS_OK,
		0,
		ফাঁকা,
		MRK_CA,
		"prometheus.example.com",
		ফাঁকা,
		চাবি_ECDSA,
		ফাঁকা,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, 0, 0, 0, -1, {
		ফাঁকা,
		37,
		HKF_STATUS_INVALID,
		0,
		ফাঁকা,
		MRK_ERROR,
		ফাঁকা,
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		38,
		HKF_STATUS_INVALID,
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ফাঁকা,
		39,
		HKF_STATUS_INVALID,
		0,
		ফাঁকা,
		MRK_NONE,
		"prometheus.example.com",
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, HKF_STATUS_OK, চাবি_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		ফাঁকা,
		41,
		HKF_STATUS_INVALID,
		0,
		ফাঁকা,
		MRK_NONE,
		"sisyphus.example.com",
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,	/* filled at runtime */
		ফাঁকা,
		0,
	} },
	{ ফাঁকা, HKF_STATUS_OK, চাবি_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		ফাঁকা,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		ফাঁকা,
		MRK_NONE,
		"prometheus.example.com",
		ফাঁকা,
		চাবি_UNSPEC,
		ফাঁকা,	/* filled at runtime */
		ফাঁকা,
		0,
	} },
};

শূন্য test_iterate(শূন্য);

শূন্য
test_iterate(শূন্য)
{
	কাঠামো cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_PARSE_চাবি;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, ফাঁকা, ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, ফাঁকা, ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", ফাঁকা, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_PARSE_চাবি;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, আকার(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = আকার(expected_full)/আকার(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_চাবি;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_তথ্য_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

