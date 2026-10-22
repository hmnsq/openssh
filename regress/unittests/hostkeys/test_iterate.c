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

ساخت expected {
	ثابت حرف *کلید_file;		/* Path for key, NULL for none */
	صحیح no_parse_حالت;		/* Expected status w/o key parsing */
	صحیح no_parse_keytype;		/* Expected keytype w/o key parsing */
	صحیح مطابقت_host_p;		/* Match 'prometheus.example.com' */
	صحیح مطابقت_host_s;		/* Match 'sisyphus.example.com' */
	صحیح مطابقت_ipv4;			/* Match '192.0.2.1' */
	صحیح مطابقت_ipv6;			/* Match '2001:db8::1' */
	صحیح مطابقت_flags;		/* Expected flags from match */
	ساخت hostkey_foreach_سطر l;	/* Expected line contents */
};

ساخت cbctx {
	ثابت ساخت expected *expected;
	سائز_t nexpected;
	سائز_t i;
	صحیح flags;
	صحیح مطابقت_host_p;
	صحیح مطابقت_host_s;
	صحیح مطابقت_ipv4;
	صحیح مطابقت_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
ساکن صحیح
check(ساخت hostkey_foreach_سطر *l, خالی *_ctx)
{
	ساخت cbctx *ctx = (ساخت cbctx *)_ctx;
	ثابت ساخت expected *expected;
	صحیح parse_کلید = (ctx->flags & HKF_WANT_PARSE_کلید) != 0;
	ثابت صحیح matching = (ctx->flags & HKF_WANT_مطابقت) != 0;
	u_int expected_حالت, expected_مطابقت;
	صحیح expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	برائے (;;) {
		ASSERT_سائز_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		اگر (!matching)
			توڑو;
		اگر (ctx->مطابقت_host_p && expected->مطابقت_host_p)
			توڑو;
		اگر (ctx->مطابقت_host_s && expected->مطابقت_host_s)
			توڑو;
		اگر (ctx->مطابقت_ipv4 && expected->مطابقت_ipv4)
			توڑو;
		اگر (ctx->مطابقت_ipv6 && expected->مطابقت_ipv6)
			توڑو;
	}
	expected_حالت = (parse_کلید || expected->no_parse_حالت < 0) ?
	    expected->l.حالت_2 : (u_int)expected->no_parse_حالت;
	expected_مطابقت = expected->l.مطابقت;
#تعریف_کرو UPDATE_مطابقت_حالت(x) کرو { \
		اگر (ctx->x && expected->x) { \
			expected_مطابقت |= expected->x; \
			اگر (expected_حالت == HKF_حالت_OK) \
				expected_حالت = HKF_حالت_MATCHED; \
		} \
	} جب (0)
	expected_keytype = (parse_کلید || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#اگر_غیر_تعریف_شدہ WITH_OPENSSL
	اگر (expected->l.keytype == کلید_RSA ||
	    expected->no_parse_keytype == کلید_RSA ||
	    expected->l.keytype == کلید_ECDSA ||
	    expected->no_parse_keytype == کلید_ECDSA)
		skip = 1;
#اگر_ختم /* WITH_OPENSSL */
	اگر (skip) {
		expected_حالت = HKF_حالت_INVALID;
		expected_keytype = کلید_UNSPEC;
		parse_کلید = 0;
	}
	UPDATE_مطابقت_حالت(مطابقت_host_p);
	UPDATE_مطابقت_حالت(مطابقت_host_s);
	UPDATE_مطابقت_حالت(مطابقت_ipv4);
	UPDATE_مطابقت_حالت(مطابقت_ipv6);

	ASSERT_PTR_NE(l->راستہ, تہی); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->حالت_2, expected_حالت);
	ASSERT_U_INT_EQ(l->مطابقت, expected_مطابقت);
	/* Not all test entries contain fulltext */
	اگر (expected->l.سطر != تہی)
		ASSERT_STRING_EQ(l->سطر, expected->l.سطر);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	اگر (expected->l.hosts != تہی)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	اگر (expected->l.rawkey != تہی)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	اگر (parse_کلید) {
		اگر (expected->l.کلید == تہی)
			ASSERT_PTR_EQ(l->کلید, تہی);
		اگر (expected->l.کلید != تہی) {
			ASSERT_PTR_NE(l->کلید, تہی);
			ASSERT_INT_EQ(sshkey_equal(l->کلید, expected->l.کلید), 1);
		}
	}
	اگر (parse_کلید && l->comment != تہی && expected->l.comment != تہی)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	واپس 0;
}

/* Loads public keys for a set of expected results */
ساکن خالی
prepare_expected(ساخت expected *expected, سائز_t n)
{
	سائز_t i;

	برائے (i = 0; i < n; i++) {
		اگر (expected[i].کلید_file == تہی)
			جاری;
#اگر_غیر_تعریف_شدہ WITH_OPENSSL
		انتخاب (expected[i].l.keytype) {
		حالت کلید_RSA:
		حالت کلید_ECDSA:
			جاری;
		}
#اگر_ختم /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_بھرو_عوامی(
		    test_ڈیٹا_file(expected[i].کلید_file), &expected[i].l.کلید,
		    تہی), 0);
	}
}

ساکن خالی
cleanup_expected(ساخت expected *expected, سائز_t n)
{
	سائز_t i;

	برائے (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.کلید);
		expected[i].l.کلید = تہی;
	}
}

ساخت expected expected_بھرا[] = {
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,				/* path, don't care */
		1,				/* line number */
		HKF_حالت_COMMENT,		/*حالت*/
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		تہی,				/* hosts text */
		تہی,				/* raw key, optional */
		کلید_UNSPEC,			/* key type */
		تہی,				/* deserialised key */
		تہی,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		2,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		3,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		4,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		5,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		6,
		HKF_حالت_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_مطابقت_HOST, 0, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		7,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_مطابقت_HOST, 0, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		8,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_مطابقت_HOST, 0, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		9,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		10,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		11,
		HKF_حالت_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_مطابقت_HOST, HKF_مطابقت_HOST, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		12,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_مطابقت_HOST, HKF_مطابقت_HOST, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		13,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_مطابقت_HOST, HKF_مطابقت_HOST, HKF_مطابقت_IP, HKF_مطابقت_IP, -1, {
		تہی,
		14,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		15,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		16,
		HKF_حالت_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, -1, {
		تہی,
		17,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, -1, {
		تہی,
		18,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, -1, {
		تہی,
		19,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		20,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, 0, -1, {
		تہی,
		21,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, 0, -1, {
		تہی,
		22,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, -1, {
		تہی,
		23,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, 0, -1, {
		تہی,
		24,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, 0, -1, {
		تہی,
		25,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, -1, {
		تہی,
		26,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_مطابقت_HOST|HKF_مطابقت_HOST_HASHED, 0, 0, 0, -1, {
		تہی,
		27,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, 0, -1, {
		تہی,
		28,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_مطابقت_IP|HKF_مطابقت_IP_HASHED, -1, {
		تہی,
		29,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_NONE,
		تہی,
		تہی,
		کلید_RSA,
		تہی,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		30,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		31,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		32,
		HKF_حالت_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		33,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_REVOKE,
		"sisyphus.example.com",
		تہی,
		کلید_ED25519,
		تہی,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_مطابقت_HOST, 0, 0, 0, -1, {
		تہی,
		34,
		HKF_حالت_OK,
		0,
		تہی,
		MRK_CA,
		"prometheus.example.com",
		تہی,
		کلید_ECDSA,
		تہی,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		35,
		HKF_حالت_COMMENT,
		0,
		"",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		36,
		HKF_حالت_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, 0, 0, 0, -1, {
		تہی,
		37,
		HKF_حالت_INVALID,
		0,
		تہی,
		MRK_ERROR,
		تہی,
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		38,
		HKF_حالت_INVALID,
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, HKF_مطابقت_HOST, 0, 0, 0, -1, {
		تہی,
		39,
		HKF_حالت_INVALID,
		0,
		تہی,
		MRK_NONE,
		"prometheus.example.com",
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, HKF_حالت_OK, کلید_ED25519, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		40,
		HKF_حالت_INVALID,	/* Would be ok if key not parsed */
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_UNSPEC,
		تہی,
		تہی,
		0,
	} },
	{ تہی, -1, -1, 0, HKF_مطابقت_HOST, 0, 0, -1, {
		تہی,
		41,
		HKF_حالت_INVALID,
		0,
		تہی,
		MRK_NONE,
		"sisyphus.example.com",
		تہی,
		کلید_UNSPEC,
		تہی,	/* filled at runtime */
		تہی,
		0,
	} },
	{ تہی, HKF_حالت_OK, کلید_RSA, HKF_مطابقت_HOST, 0, 0, 0, -1, {
		تہی,
		42,
		HKF_حالت_INVALID,	/* Would be ok if key not parsed */
		0,
		تہی,
		MRK_NONE,
		"prometheus.example.com",
		تہی,
		کلید_UNSPEC,
		تہی,	/* filled at runtime */
		تہی,
		0,
	} },
};

خالی test_iterate(خالی);

خالی
test_iterate(خالی)
{
	ساخت cbctx ctx;

	TEST_آغاز("hostkeys_iterate all with key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_PARSE_کلید;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, تہی, تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate all without key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, تہی, تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify host 1");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	ctx.مطابقت_host_p = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify host 2");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	ctx.مطابقت_host_s = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match host 1");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	ctx.مطابقت_host_p = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match host 2");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	ctx.مطابقت_host_s = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify host missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match host missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", تہی, ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	ctx.مطابقت_ipv4 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	ctx.مطابقت_ipv6 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	ctx.مطابقت_ipv4 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	ctx.مطابقت_ipv6 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify addr missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match addr missing");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify host 2 and IPv4");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = 0;
	ctx.مطابقت_host_s = 1;
	ctx.مطابقت_ipv4 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match host 1 and IPv6");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت;
	ctx.مطابقت_host_p = 1;
	ctx.مطابقت_ipv6 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_PARSE_کلید;
	ctx.مطابقت_host_s = 1;
	ctx.مطابقت_ipv4 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();

	TEST_آغاز("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	memset(&ctx, 0, حجم(ctx));
	ctx.expected = expected_بھرا;
	ctx.nexpected = حجم(expected_بھرا)/حجم(*expected_بھرا);
	ctx.flags = HKF_WANT_مطابقت|HKF_WANT_PARSE_کلید;
	ctx.مطابقت_host_p = 1;
	ctx.مطابقت_ipv6 = 1;
	prepare_expected(expected_بھرا, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_ڈیٹا_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_بھرا, ctx.nexpected);
	TEST_مکمل();
}

