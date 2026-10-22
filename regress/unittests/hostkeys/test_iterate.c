/* 	$OpenBSD: test_iterate.c,v 1.11 2025/11/17 09:59:13 dtucker Exp $ */
/*
 * Regress test for hostfile.h hostkeys_foreach()
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "sshkey.h"
#समावेश "authfile.h"
#समावेश "hostfile.h"

काष्ठा expected {
	स्थिर अक्षर *कुंजी_file;		/* Path for key, NULL for none */
	पूर्णांक no_parse_status;		/* Expected status w/o key parsing */
	पूर्णांक no_parse_keytype;		/* Expected keytype w/o key parsing */
	पूर्णांक match_host_p;		/* Match 'prometheus.example.com' */
	पूर्णांक match_host_s;		/* Match 'sisyphus.example.com' */
	पूर्णांक match_ipv4;			/* Match '192.0.2.1' */
	पूर्णांक match_ipv6;			/* Match '2001:db8::1' */
	पूर्णांक match_flags;		/* Expected flags from match */
	काष्ठा hostkey_foreach_पंक्ति l;	/* Expected line contents */
};

काष्ठा cbctx {
	स्थिर काष्ठा expected *expected;
	माप_प्रकार nexpected;
	माप_प्रकार i;
	पूर्णांक flags;
	पूर्णांक match_host_p;
	पूर्णांक match_host_s;
	पूर्णांक match_ipv4;
	पूर्णांक match_ipv6;
};

/*
 * hostkeys_foreach() iterator callback that verifies the line passed
 * against an array of expected entries.
 */
अटल पूर्णांक
check(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *_ctx)
{
	काष्ठा cbctx *ctx = (काष्ठा cbctx *)_ctx;
	स्थिर काष्ठा expected *expected;
	पूर्णांक parse_कुंजी = (ctx->flags & HKF_WANT_PARSE_कुंजी) != 0;
	स्थिर पूर्णांक matching = (ctx->flags & HKF_WANT_MATCH) != 0;
	u_int expected_status, expected_match;
	पूर्णांक expected_keytype, skip = 0;

	test_subtest_info("entry %zu/%zu, file line %ld",
	    ctx->i + 1, ctx->nexpected, l->linenum);

	क्रम (;;) {
		ASSERT_आकार_T_LT(ctx->i, ctx->nexpected);
		expected = ctx->expected + ctx->i++;
		/* If we are matching host/IP then skip entries that don't */
		अगर (!matching)
			अवरोध;
		अगर (ctx->match_host_p && expected->match_host_p)
			अवरोध;
		अगर (ctx->match_host_s && expected->match_host_s)
			अवरोध;
		अगर (ctx->match_ipv4 && expected->match_ipv4)
			अवरोध;
		अगर (ctx->match_ipv6 && expected->match_ipv6)
			अवरोध;
	}
	expected_status = (parse_कुंजी || expected->no_parse_status < 0) ?
	    expected->l.status : (u_int)expected->no_parse_status;
	expected_match = expected->l.match;
#घोषणा UPDATE_MATCH_STATUS(x) करो { \
		अगर (ctx->x && expected->x) { \
			expected_match |= expected->x; \
			अगर (expected_status == HKF_STATUS_OK) \
				expected_status = HKF_STATUS_MATCHED; \
		} \
	} जबतक (0)
	expected_keytype = (parse_कुंजी || expected->no_parse_keytype < 0) ?
	    expected->l.keytype : expected->no_parse_keytype;

#अगर_अघोषित WITH_OPENSSL
	अगर (expected->l.keytype == कुंजी_RSA ||
	    expected->no_parse_keytype == कुंजी_RSA ||
	    expected->l.keytype == कुंजी_ECDSA ||
	    expected->no_parse_keytype == कुंजी_ECDSA)
		skip = 1;
#पूर्ण_अगर /* WITH_OPENSSL */
	अगर (skip) {
		expected_status = HKF_STATUS_INVALID;
		expected_keytype = कुंजी_UNSPEC;
		parse_कुंजी = 0;
	}
	UPDATE_MATCH_STATUS(match_host_p);
	UPDATE_MATCH_STATUS(match_host_s);
	UPDATE_MATCH_STATUS(match_ipv4);
	UPDATE_MATCH_STATUS(match_ipv6);

	ASSERT_PTR_NE(l->path, शून्य); /* Don't care about path */
	ASSERT_LONG_LONG_EQ(l->linenum, expected->l.linenum);
	ASSERT_U_INT_EQ(l->status, expected_status);
	ASSERT_U_INT_EQ(l->match, expected_match);
	/* Not all test entries contain fulltext */
	अगर (expected->l.पंक्ति != शून्य)
		ASSERT_STRING_EQ(l->पंक्ति, expected->l.पंक्ति);
	ASSERT_INT_EQ(l->marker, expected->l.marker);
	/* XXX we skip hashed hostnames for now; implement checking */
	अगर (expected->l.hosts != शून्य)
		ASSERT_STRING_EQ(l->hosts, expected->l.hosts);
	/* Not all test entries contain raw keys */
	अगर (expected->l.rawkey != शून्य)
		ASSERT_STRING_EQ(l->rawkey, expected->l.rawkey);
	/* XXX synthesise raw key for cases lacking and compare */
	ASSERT_INT_EQ(l->keytype, expected_keytype);
	अगर (parse_कुंजी) {
		अगर (expected->l.कुंजी == शून्य)
			ASSERT_PTR_EQ(l->कुंजी, शून्य);
		अगर (expected->l.कुंजी != शून्य) {
			ASSERT_PTR_NE(l->कुंजी, शून्य);
			ASSERT_INT_EQ(sshkey_equal(l->कुंजी, expected->l.कुंजी), 1);
		}
	}
	अगर (parse_कुंजी && l->comment != शून्य && expected->l.comment != शून्य)
		ASSERT_STRING_EQ(l->comment, expected->l.comment);
	वापस 0;
}

/* Loads public keys for a set of expected results */
अटल व्योम
prepare_expected(काष्ठा expected *expected, माप_प्रकार n)
{
	माप_प्रकार i;

	क्रम (i = 0; i < n; i++) {
		अगर (expected[i].कुंजी_file == शून्य)
			जारी;
#अगर_अघोषित WITH_OPENSSL
		चयन (expected[i].l.keytype) {
		हाल कुंजी_RSA:
		हाल कुंजी_ECDSA:
			जारी;
		}
#पूर्ण_अगर /* WITH_OPENSSL */
		ASSERT_INT_EQ(sshkey_load_public(
		    test_तथ्य_file(expected[i].कुंजी_file), &expected[i].l.कुंजी,
		    शून्य), 0);
	}
}

अटल व्योम
cleanup_expected(काष्ठा expected *expected, माप_प्रकार n)
{
	माप_प्रकार i;

	क्रम (i = 0; i < n; i++) {
		sshkey_free(expected[i].l.कुंजी);
		expected[i].l.कुंजी = शून्य;
	}
}

काष्ठा expected expected_full[] = {
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,				/* path, don't care */
		1,				/* line number */
		HKF_STATUS_COMMENT,		/* status */
		0,				/* match flags */
		"# Plain host keys, plain host names", /* full line, optional */
		MRK_NONE,			/* marker (CA / revoked) */
		शून्य,				/* hosts text */
		शून्य,				/* raw key, optional */
		कुंजी_UNSPEC,			/* key type */
		शून्य,				/* deserialised key */
		शून्य,				/* comment */
		0,				/* note */
	} },
	{ "ecdsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		2,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #1",
		0,
	} },
	{ "ed25519_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		3,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #1",
		0,
	} },
	{ "rsa_1.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		4,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #1",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		5,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		6,
		HKF_STATUS_COMMENT,
		0,
		"# Plain host keys, hostnames + addresses",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ "ecdsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		7,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #2",
		0,
	} },
	{ "ed25519_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		8,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #2",
		0,
	} },
	{ "rsa_2.pub" , -1, -1, HKF_MATCH_HOST, 0, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		9,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"prometheus.example.com,192.0.2.1,2001:db8::1",
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #2",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		10,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		11,
		HKF_STATUS_COMMENT,
		0,
		"# Some hosts with wildcard names / IPs",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ "ecdsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		12,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #3",
		0,
	} },
	{ "ed25519_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		13,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #3",
		0,
	} },
	{ "rsa_3.pub" , -1, -1, HKF_MATCH_HOST, HKF_MATCH_HOST, HKF_MATCH_IP, HKF_MATCH_IP, -1, {
		शून्य,
		14,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		"*.example.com,192.0.2.*,2001:*",
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #3",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		15,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		16,
		HKF_STATUS_COMMENT,
		0,
		"# Hashed hostname and address entries",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ "ecdsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		शून्य,
		17,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #5",
		0,
	} },
	{ "ed25519_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		शून्य,
		18,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #5",
		0,
	} },
	{ "rsa_5.pub" , -1, -1, 0, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, -1, {
		शून्य,
		19,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #5",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		20,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	/*
	 * The next series have each key listed multiple times, as the
	 * hostname and addresses in the pre-hashed known_hosts are split
	 * to separate lines.
	 */
	{ "ecdsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		शून्य,
		21,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		शून्य,
		22,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ecdsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		शून्य,
		23,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		शून्य,
		24,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		शून्य,
		25,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "ed25519_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		शून्य,
		26,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, HKF_MATCH_HOST|HKF_MATCH_HOST_HASHED, 0, 0, 0, -1, {
		शून्य,
		27,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, 0, -1, {
		शून्य,
		28,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ "rsa_6.pub" , -1, -1, 0, 0, 0, HKF_MATCH_IP|HKF_MATCH_IP_HASHED, -1, {
		शून्य,
		29,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_RSA,
		शून्य,	/* filled at runtime */
		"RSA #6",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		30,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		31,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		32,
		HKF_STATUS_COMMENT,
		0,
		"# Revoked and CA keys",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ "ed25519_4.pub" , -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		33,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_REVOKE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_ED25519,
		शून्य,	/* filled at runtime */
		"ED25519 #4",
		0,
	} },
	{ "ecdsa_4.pub" , -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		शून्य,
		34,
		HKF_STATUS_OK,
		0,
		शून्य,
		MRK_CA,
		"prometheus.example.com",
		शून्य,
		कुंजी_ECDSA,
		शून्य,	/* filled at runtime */
		"ECDSA #4",
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		35,
		HKF_STATUS_COMMENT,
		0,
		"",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		36,
		HKF_STATUS_COMMENT,
		0,
		"# Some invalid lines",
		MRK_NONE,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, 0, 0, 0, -1, {
		शून्य,
		37,
		HKF_STATUS_INVALID,
		0,
		शून्य,
		MRK_ERROR,
		शून्य,
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		38,
		HKF_STATUS_INVALID,
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, HKF_MATCH_HOST, 0, 0, 0, -1, {
		शून्य,
		39,
		HKF_STATUS_INVALID,
		0,
		शून्य,
		MRK_NONE,
		"prometheus.example.com",
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, HKF_STATUS_OK, कुंजी_ED25519, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		40,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_UNSPEC,
		शून्य,
		शून्य,
		0,
	} },
	{ शून्य, -1, -1, 0, HKF_MATCH_HOST, 0, 0, -1, {
		शून्य,
		41,
		HKF_STATUS_INVALID,
		0,
		शून्य,
		MRK_NONE,
		"sisyphus.example.com",
		शून्य,
		कुंजी_UNSPEC,
		शून्य,	/* filled at runtime */
		शून्य,
		0,
	} },
	{ शून्य, HKF_STATUS_OK, कुंजी_RSA, HKF_MATCH_HOST, 0, 0, 0, -1, {
		शून्य,
		42,
		HKF_STATUS_INVALID,	/* Would be ok if key not parsed */
		0,
		शून्य,
		MRK_NONE,
		"prometheus.example.com",
		शून्य,
		कुंजी_UNSPEC,
		शून्य,	/* filled at runtime */
		शून्य,
		0,
	} },
};

व्योम test_iterate(व्योम);

व्योम
test_iterate(व्योम)
{
	काष्ठा cbctx ctx;

	TEST_START("hostkeys_iterate all with key parse");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_PARSE_कुंजी;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, शून्य, शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate all without key parse");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, शून्य, शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 1");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "prometheus.example.com", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 2");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_s = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host missing");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host missing");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "actaeon.example.org", शून्य, ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv4");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify IPv6");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv4");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match IPv6");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "2001:db8::1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify addr missing");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "192.168.0.1",
	    ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match addr missing");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "tiresias.example.org", "::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = 0;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate specify host 2 and IPv4 w/ key parse");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_PARSE_कुंजी;
	ctx.match_host_s = 1;
	ctx.match_ipv4 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "sisyphus.example.com", "192.0.2.1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();

	TEST_START("hostkeys_iterate match host 1 and IPv6 w/ key parse");
	स_रखो(&ctx, 0, माप(ctx));
	ctx.expected = expected_full;
	ctx.nexpected = माप(expected_full)/माप(*expected_full);
	ctx.flags = HKF_WANT_MATCH|HKF_WANT_PARSE_कुंजी;
	ctx.match_host_p = 1;
	ctx.match_ipv6 = 1;
	prepare_expected(expected_full, ctx.nexpected);
	ASSERT_INT_EQ(hostkeys_foreach(test_तथ्य_file("known_hosts"),
	    check, &ctx, "prometheus.example.com",
	    "2001:db8::1", ctx.flags, 0), 0);
	cleanup_expected(expected_full, ctx.nexpected);
	TEST_DONE();
}

