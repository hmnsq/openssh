/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "hostfile.h"

संरचना expected {
	ध्रुव वर्ण *कुञ्चिका_file;		/* Path for key, NULL for none */
	पूर्णाङ्क no_parse_स्थितिः;		/* Expected status w/o key parsing */
	पूर्णाङ्क no_parse_keytype;		/* Expected keytype w/o key parsing */
	पूर्णाङ्क मेलनम्_host_p;		/* Match 'prometheus.example.com' */
	पूर्णाङ्क मेलनम्_host_s;		/* Match 'sisyphus.example.com' */
	पूर्णाङ्क मेलनम्_ipv4;			/* Match '192.0.2.1' */
	पूर्णाङ्क मेलनम्_ipv6;			/* Match '2001:db8::1' */
	पूर्णाङ्क मेलनम्_flags;		/* Expected flags from match */
	संरचना hostkey_foreach_पङ्क्तिः l;	/* Expected line contents */
};

संरचना cbctx {
	ध्रुव संरचना expected *expected;
	आकार_t nexpected;
	आकार_t i;
	पूर्णाङ्क flags;
	पूर्णाङ्क मेलनम्_host_p;
	पूर्णाङ्क मेलनम्_host_s;
	पूर्णाङ्क मेलनम्_ipv4;
	पूर्णाङ्क मेलनम्_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
स्थिर पूर्णाङ्क
check(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *_ctx)
{
	संरचना cbctx *ctx = (संरचना cbctx *)_ctx;
	ध्रुव संरचना expected *expected;
	पूर्णाङ्क parse_कुञ्चिका = (ctx->flags & HKF_WANT_PARSE_कुञ्चिका) != 0;
	ध्रुव पूर्णाङ्क matching = (ctx->flags & HKF_WANT_मेलनम्) != 0;
	u_int expected_स्थितिः, expected_मेलनम्;
	पूर्णाङ्क expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	प्रति (;;) {
		ASSERT_आकार_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		यदि (!matching)
			भङ्ग;
		यदि (ctx->मेलनम्_host_p && expected->मेलनम्_host_p)
			भङ्ग;
		यदि (ctx->मेलनम्_host_s && expected->मेलनम्_host_s)
			भङ्ग;
		यदि (ctx->मेलनम्_ipv4 && expected->मेलनम्_ipv4)
			भङ्ग;
		यदि (ctx->मेलनम्_ipv6 && expected->मेलनम्_ipv6)
			भङ्ग;
	}
	expected_स्थितिः = (parse_कुञ्चिका || expected->no_parse_स्थितिः < 0) ?
	    expected->l.स्थितिः : (u_int)expected->no_parse_स्थितिः;
	expected_मेलनम् = expected->l.मेलनम्;
#परिभाषय UPDATE_मेलनम्_स्थितिः(x) कुरु { \
		यदि (ctx->x && expected->x) { \
			expected_मेलनम् |= expected->x; \
			यदि (expected_स्थितिः == HKF_स्थितिः_OK) \
				expected_स्थितिः = HKF_स्थितिः_MATCHED; \
		} \
	} यावत् (0)
	expected_keytype = (parse_कुञ्चिका || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#यदि_अपरिभाषितम् WITH_OPENSSL
	यदि (expected->l.keytype == कुञ्चिका_RSA ||
	    expected->no_parse_keytype == कुञ्चिका_RSA ||
	    expected->l.keytype == कुञ्चिका_ECDSA ||
	    expected->no_parse_keytype == कुञ्चिका_ECDSA)
		skip = 1;
#यदि_अन्तः /* WITH_OPENSSL */
	यदि (skip) {
		expected_स्थितिः = HKF_स्थितिः_INVALID;
		expected_keytype = कुञ्चिका_UNSPEC;
		parse_कुञ्चिका = 0;
	}
	UPDATE_मेलनम्_स्थितिः(मेलनम्_host_p);
	UPDATE_मेलनम्_स्थितिः(मेलनम्_host_s);
	UPDATE_मेलनम्_स्थितिः(मेलनम्_ipv4);
	UPDATE_मेलनम्_स्थितिः(मेलनम्_ipv6);

	ASSERT_PTR_NE(l->मार्गः, रिक्त); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->स्थितिः, expected_स्थितिः);
	ASSERT_U_INT_EQ(l->मेलनम्, expected_मेलनम्);
	/* Not all test entries contain fulltext */
	यदि (expected->l.पङ्क्तिः != रिक्त)
		ASSERT_STRING_EQ(l->पङ्क्तिः, expected->l.पङ्क्तिः);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	यदि (expected->l.hosts != रिक्त)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	यदि (expected->l.rawkey != रिक्त)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	यदि (parse_कुञ्चिका) {
		यदि (expected->l.कुञ्चिका == रिक्त)
			ASSERT_PTR_EQ(l->कुञ्चिका, रिक्त);
		यदि (expected->l.कुञ्चिका != रिक्त) {
			ASSERT_PTR_NE(l->कुञ्चिका, रिक्त);
			ASSERT_INT_EQ(sshkey_equal(l->कुञ्चिका, expected->l.कुञ्चिका), 1);
		}
	}
	यदि (parse_कुञ्चिका && l->comment != रिक्त && expected->l.comment != रिक्त)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	प्रत्यागम 0;
}

/* Loads public keys for a set of expected results */
स्थिर शून्य
prepare_expected(संरचना expected *expected, आकार_t n)
{
	आकार_t i;

	प्रति (i = 0; i < n; i++) {
		यदि (expected[i].कुञ्चिका_file == रिक्त)
			अनुवर्त;
#यदि_अपरिभाषितम् WITH_OPENSSL
		विकल्प (expected[i].l.keytype) {
		पक्ष कुञ्चिका_RSA:
		पक्ष कुञ्चिका_ECDSA:
			अनुवर्त;
		}
#यदि_अन्तः /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_आरोपय_लौकिकम्(
		    test_दत्त_file(expected[i].कुञ्चिका_file), &expected[i].l.कुञ्चिका,
		    रिक्त), 0);
	}
}

स्थिर शून्य
cleanup_expected(संरचना expected *expected, आकार_t n)
{
	आकार_t i;

	प्रति (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.कुञ्चिका);
		expected[i].l.कुञ्चिका = रिक्त;
	}
}

संरचना expected expected_पूर्णम्[] = {
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,				/* path, don't care */
		1,				/* line number */
		HKF_स्थितिः_COMMENT,		/*स्थितिः*/
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		रिक्त,				/* hosts text */
		रिक्त,				/* raw key, optional */
		कुञ्चिका_UNSPEC,			/* key type */
		रिक्त,				/* deserialised key */
		रिक्त,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		2,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		3,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		4,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		5,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		6,
		HKF_स्थितिः_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_मेलनम्_HOST, 0, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		7,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_मेलनम्_HOST, 0, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		8,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_मेलनम्_HOST, 0, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		9,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		10,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		11,
		HKF_स्थितिः_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_मेलनम्_HOST, HKF_मेलनम्_HOST, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		12,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_मेलनम्_HOST, HKF_मेलनम्_HOST, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		13,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_मेलनम्_HOST, HKF_मेलनम्_HOST, HKF_मेलनम्_IP, HKF_मेलनम्_IP, -1, {
		रिक्त,
		14,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		15,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		16,
		HKF_स्थितिः_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		17,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		18,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		19,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		20,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		21,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, 0, -1, {
		रिक्त,
		22,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, -1, {
		रिक्त,
		23,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		24,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, 0, -1, {
		रिक्त,
		25,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, -1, {
		रिक्त,
		26,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_मेलनम्_HOST|HKF_मेलनम्_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		27,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, 0, -1, {
		रिक्त,
		28,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_मेलनम्_IP|HKF_मेलनम्_IP_HASHED, -1, {
		रिक्त,
		29,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		30,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		31,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		32,
		HKF_स्थितिः_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		33,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_REVOKE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_मेलनम्_HOST, 0, 0, 0, -1, {
		रिक्त,
		34,
		HKF_स्थितिः_OK,
		0,
		रिक्त,
		MRK_CA,
		"prometheus.example.com",
		रिक्त,
		कुञ्चिका_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		35,
		HKF_स्थितिः_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		36,
		HKF_स्थितिः_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		37,
		HKF_स्थितिः_INVALID,
		0,
		रिक्त,
		MRK_ERROR,
		रिक्त,
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		38,
		HKF_स्थितिः_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, HKF_मेलनम्_HOST, 0, 0, 0, -1, {
		रिक्त,
		39,
		HKF_स्थितिः_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com",
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, HKF_स्थितिः_OK, कुञ्चिका_ED25519, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		40,
		HKF_स्थितिः_INVALID,	/* Would be ok if key not parsed */
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, HKF_मेलनम्_HOST, 0, 0, -1, {
		रिक्त,
		41,
		HKF_स्थितिः_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,	/* filled at runtime */
		रिक्त,
		0,
	} },
	{ रिक्त, HKF_स्थितिः_OK, कुञ्चिका_RSA, HKF_मेलनम्_HOST, 0, 0, 0, -1, {
		रिक्त,
		42,
		HKF_स्थितिः_INVALID,	/* Would be ok if key not parsed */
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com",
		रिक्त,
		कुञ्चिका_UNSPEC,
		रिक्त,	/* filled at runtime */
		रिक्त,
		0,
	} },
};

शून्य test_iterate(शून्य);

शून्य
test_iterate(शून्य)
{
	संरचना cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_PARSE_कुञ्चिका;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, रिक्त, रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate all without key parse");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, रिक्त, रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify host 1");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	ctx.मेलनम्_host_p = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify host 2");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	ctx.मेलनम्_host_s = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match host 1");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	ctx.मेलनम्_host_p = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match host 2");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	ctx.मेलनम्_host_s = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify host missing");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match host missing");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify IPv4");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	ctx.मेलनम्_ipv4 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify IPv6");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	ctx.मेलनम्_ipv6 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match IPv4");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	ctx.मेलनम्_ipv4 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match IPv6");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	ctx.मेलनम्_ipv6 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify addr missing");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match addr missing");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = 0;
	ctx.मेलनम्_host_s = 1;
	ctx.मेलनम्_ipv4 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्;
	ctx.मेलनम्_host_p = 1;
	ctx.मेलनम्_ipv6 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_PARSE_कुञ्चिका;
	ctx.मेलनम्_host_s = 1;
	ctx.मेलनम्_ipv4 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	स्मृतिं_पूरय(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_पूर्णम्;
	ctx.nexpected = परिमाण(expected_पूर्णम्)/परिमाण(*expected_पूर्णम्);
	ctx.flags = HKF_WANT_मेलनम्|HKF_WANT_PARSE_कुञ्चिका;
	ctx.मेलनम्_host_p = 1;
	ctx.मेलनम्_ipv6 = 1;
	prepare_expected(expected_पूर्णम्, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_दत्त_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_पूर्णम्, ctx.nexpected);
	TEST_समाप्तम्();
}

