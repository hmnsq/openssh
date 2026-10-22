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
	अचर वर्ण *साँचो_file;		/* Path for key, NULL for none */
	पूर्णाङ्क no_parse_status;		/* Expected status w/o key parsing */
	पूर्णाङ्क no_parse_keytype;		/* Expected keytype w/o key parsing */
	पूर्णाङ्क match_host_p;		/* Match 'prometheus.example.com' */
	पूर्णाङ्क match_host_s;		/* Match 'sisyphus.example.com' */
	पूर्णाङ्क match_ipv4;			/* Match '192.0.2.1' */
	पूर्णाङ्क match_ipv6;			/* Match '2001:db8::1' */
	पूर्णाङ्क match_flags;		/* Expected flags from match */
	संरचना hostkey_foreach_पङ्क्ति l;	/* Expected line contents */
};

संरचना cbctx {
	अचर संरचना expected *expected;
	माप_प्रकार nexpected;
	माप_प्रकार i;
	पूर्णाङ्क flags;
	पूर्णाङ्क match_host_p;
	पूर्णाङ्क match_host_s;
	पूर्णाङ्क match_ipv4;
	पूर्णाङ्क match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
स्थिर पूर्णाङ्क
check(संरचना hostkey_foreach_पङ्क्ति *l, शून्य *_ctx)
{
	संरचना cbctx *ctx = (संरचना cbctx *)_ctx;
	अचर संरचना expected *expected;
	पूर्णाङ्क parse_साँचो = (ctx->flags & HKF_WANT_PARSE_साँचो) != 0;
	अचर पूर्णाङ्क matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	पूर्णाङ्क expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	लागि (;;) {
		ASSERT_SIZE_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		यदि (!matching)
			रोक;
		यदि (ctx->match_host_p && expected->match_host_p)
			रोक;
		यदि (ctx->match_host_s && expected->match_host_s)
			रोक;
		यदि (ctx->match_ipv4 && expected->match_ipv4)
			रोक;
		यदि (ctx->match_ipv6 && expected->match_ipv6)
			रोक;
	}
	expected_status = (parse_साँचो || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#define UPDATE_MATCH_STATUS(x) गर { \
		यदि (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			यदि (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} जबसम्म (0)
	expected_keytype = (parse_साँचो || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#ifndef WITH_OPENSSL
	यदि (expected->l.keytype == साँचो_RSA ||
	    expected->no_parse_keytype == साँचो_RSA ||
	    expected->l.keytype == साँचो_ECDSA ||
	    expected->no_parse_keytype == साँचो_ECDSA)
		skip = 1;
#endif /* WITH_OPENSSL */
	यदि (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = साँचो_UNSPEC;
		parse_साँचो = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, रिक्त); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	यदि (expected->l.पङ्क्ति != रिक्त)
		ASSERT_STRING_EQ(l->पङ्क्ति, expected->l.पङ्क्ति);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	यदि (expected->l.hosts != रिक्त)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	यदि (expected->l.rawkey != रिक्त)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	यदि (parse_साँचो) {
		यदि (expected->l.साँचो == रिक्त)
			ASSERT_PTR_EQ(l->साँचो, रिक्त);
		यदि (expected->l.साँचो != रिक्त) {
			ASSERT_PTR_NE(l->साँचो, रिक्त);
			ASSERT_INT_EQ(sshkey_equal(l->साँचो, expected->l.साँचो), 1);
		}
	}
	यदि (parse_साँचो && l->comment != रिक्त && expected->l.comment != रिक्त)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	फर्काऊ 0;
}

/* Loads public keys for a set of expected results */
स्थिर शून्य
prepare_expected(संरचना expected *expected, माप_प्रकार n)
{
	माप_प्रकार i;

	लागि (i = 0; i < n; i++) {
		यदि (expected[i].साँचो_file == रिक्त)
			जारी;
#ifndef WITH_OPENSSL
		विकल्प (expected[i].l.keytype) {
		पक्ष साँचो_RSA:
		पक्ष साँचो_ECDSA:
			जारी;
		}
#endif /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_data_file(expected[i].साँचो_file), &expected[i].l.साँचो,
		    रिक्त), 0);
	}
}

स्थिर शून्य
cleanup_expected(संरचना expected *expected, माप_प्रकार n)
{
	माप_प्रकार i;

	लागि (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.साँचो);
		expected[i].l.साँचो = रिक्त;
	}
}

संरचना expected expected_full[] = {
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		रिक्त,				/* hosts text */
		रिक्त,				/* raw key, optional */
		साँचो_UNSPEC,			/* key type */
		रिक्त,				/* deserialised key */
		रिक्त,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		2,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		3,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		4,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		7,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		8,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		9,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		12,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		13,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		रिक्त,
		14,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		17,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		18,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		रिक्त,
		19,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		21,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		रिक्त,
		22,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		रिक्त,
		23,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		24,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		रिक्त,
		25,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		रिक्त,
		26,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		रिक्त,
		27,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		रिक्त,
		28,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		रिक्त,
		29,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_RSA,
		रिक्त,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		33,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_REVOKE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_ED25519,
		रिक्त,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		रिक्त,
		34,
		HKF_STATUS_OK,
		0,
		रिक्त,
		MRK_CA,
		"prometheus.example.com",
		रिक्त,
		साँचो_ECDSA,
		रिक्त,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, 0, 0, 0, -1, {
		रिक्त,
		37,
		HKF_STATUS_INVALID,
		0,
		रिक्त,
		MRK_ERROR,
		रिक्त,
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		38,
		HKF_STATUS_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		रिक्त,
		39,
		HKF_STATUS_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com",
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, HKF_STATUS_OK, साँचो_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,
		रिक्त,
		0,
	} },
	{ रिक्त, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		रिक्त,
		41,
		HKF_STATUS_INVALID,
		0,
		रिक्त,
		MRK_NONE,
		"sisyphus.example.com",
		रिक्त,
		साँचो_UNSPEC,
		रिक्त,	/* filled at runtime */
		रिक्त,
		0,
	} },
	{ रिक्त, HKF_STATUS_OK, साँचो_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		रिक्त,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		रिक्त,
		MRK_NONE,
		"prometheus.example.com",
		रिक्त,
		साँचो_UNSPEC,
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
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_PARSE_साँचो;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, रिक्त, रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, रिक्त, रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", रिक्त, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
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
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_PARSE_साँचो;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	स_रखो(&ctx, 0, परिमाण(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = परिमाण(expected_full)/परिमाण(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_साँचो;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_data_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

