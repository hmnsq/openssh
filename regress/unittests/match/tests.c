/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
స్థిర పూర్ణాంకం
సరిపోలిక_నమూనా_original(స్థిరరాశి అక్షరం *s, స్థిరరాశి అక్షరం *నమూనా)
{
	కొరకు (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ఒకవేళ (!*నమూనా)
			తిరిగి !*s;

		ఒకవేళ (*నమూనా == '*') {
			/* Skip this and any consecutive asterisks. */
			అయితే (*నమూనా == '*')
				నమూనా++;

			/* If at end of pattern, accept immediately. */
			ఒకవేళ (!*నమూనా)
				తిరిగి 1;

			/* If next character in pattern is known, optimize. */
			ఒకవేళ (*నమూనా != '?' && *నమూనా != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				కొరకు (; *s; s++)
					ఒకవేళ (*s == *నమూనా &&
					    సరిపోలిక_నమూనా_original(s + 1,
					    నమూనా + 1))
						తిరిగి 1;
				/* Failed. */
				తిరిగి 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			కొరకు (; *s; s++)
				ఒకవేళ (సరిపోలిక_నమూనా_original(s, నమూనా))
					తిరిగి 1;
			/* Failed. */
			తిరిగి 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ఒకవేళ (!*s)
			తిరిగి 0;

		/* Check if the next character of the string is acceptable. */
		ఒకవేళ (*నమూనా != '?' && *నమూనా != *s)
			తిరిగి 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		నమూనా++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
స్థిర కొలత_t
pow_కొలత(కొలత_t పునాది, కొలత_t ఘాతాంకం)
{
	కొలత_t r = 1;

	ASSERT_కొలత_T_NE(పునాది, 0);
	అయితే (ఘాతాంకం-- != 0) {
		ASSERT_కొలత_T_LE(r, SIZE_MAX / పునాది);
		r *= పునాది;
	}
	తిరిగి r;
}

స్థిర శూన్య
make_మాట(కొలత_t v, స్థిరరాశి అక్షరం *alphabet, కొలత_t alphabet_len,
    అక్షరం *మాట, కొలత_t wordlen)
{
	కొలత_t i;

	కొరకు (i = 0; i < wordlen; i++) {
		మాట[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	మాట[wordlen] = '\0';
}

#నిర్వచించు నమూనా_LEN	8
#నిర్వచించు ఆదానం_LEN	7

స్థిర శూన్య
సరిపోలిక_నమూనా_check_one_ఆదానం(స్థిరరాశి అక్షరం *ఆదానం, స్థిరరాశి అక్షరం *నమూనా_alphabet)
{
	అక్షరం నమూనా[నమూనా_LEN];
	కొలత_t len, i, npatterns;
	పూర్ణాంకం actual, expected;

	కొరకు (len = 0; len < పరిమాణం(నమూనా); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_కొలత(అక్షరశ్రేణి_పొడవు(నమూనా_alphabet), len);
		కొరకు (i = 0; i < npatterns; i++) {
			make_మాట(i, నమూనా_alphabet,
			    అక్షరశ్రేణి_పొడవు(నమూనా_alphabet), నమూనా, len);
			actual = సరిపోలిక_నమూనా(ఆదానం, నమూనా);
			expected = సరిపోలిక_నమూనా_original(ఆదానం, నమూనా);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    ఆదానం, నమూనా);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
స్థిర శూన్య
సరిపోలిక_నమూనా_exhaustive_original(శూన్య)
{
	స్థిరరాశి అక్షరం *నమూనా_alphabet = "abx?*";
	స్థిరరాశి అక్షరం *ఆదానం_alphabet = "abc";
	అక్షరం ఆదానం[ఆదానం_LEN];
	కొలత_t len, i, ninputs;

	కొరకు (len = 0; len < పరిమాణం(ఆదానం); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_కొలత(అక్షరశ్రేణి_పొడవు(ఆదానం_alphabet), len);
		కొరకు (i = 0; i < ninputs; i++) {
			make_మాట(i, ఆదానం_alphabet,
			    అక్షరశ్రేణి_పొడవు(ఆదానం_alphabet), ఆదానం, len);
			సరిపోలిక_నమూనా_check_one_ఆదానం(ఆదానం, నమూనా_alphabet);
		}
	}
}

శూన్య
tests(శూన్య)
{
	TEST_ప్రారంభం("match_pattern");
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", ""), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "aaa"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aaa", ""), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "abc"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "abd"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "abcd"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abcd", "abc"), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("match_pattern wildcard");
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "**"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "***"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "*?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "?*"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("", "**a*"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("a", "?"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "a?"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("a", "*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "a*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "?*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "?a"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "*a"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ba", "a?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ba", "a*"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "?a"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "*a"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aa", "**"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "a***b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("axb", "a***b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("axxb", "a***b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ax", "a***b"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "*b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "*a*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "*a*b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "*a*c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a?c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "??c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "???"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a?d"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "???"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "ab*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "ab*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("a", "ab*"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "ab?"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "ab?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abcd", "ab?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "?bc"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "?b*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "?c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a*?c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ac", "a*?c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a?*c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ac", "a?*c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "?*c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ac", "?*c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("c", "?*c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "*?c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ac", "*?c"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("c", "*?c"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a?*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "a?*"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("a", "a?*"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abc", "a*?"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("ab", "a*?"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("a", "a*?"), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abb", "a*b"), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా("abbc", "a*b"), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("match_pattern exhaustive original");
	సరిపోలిక_నమూనా_exhaustive_original();
	TEST_పూర్తి();

	TEST_ప్రారంభం("match_pattern_list");
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "*", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "!*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "", 0), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "*", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("b", "!*,a", 0), -1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("match_pattern_list lowercase");
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(సరిపోలిక_నమూనా_list("ABC", "abc", 1), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("addr_match_list");
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_సరిపోలిక_list(ఖాళీ, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list(ఖాళీ, "*"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_సరిపోలిక_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_పూర్తి();

#నిర్వచించు CHECK_FILTER(string,filter,expected) \
	చేయి { \
		అక్షరం *ఫలితం = సరిపోలిక_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(ఫలితం, expected); \
		విడుదల(ఫలితం); \
	} అయితే (0)

	TEST_ప్రారంభం("match_filter_list");
	CHECK_FILTER("a,b,c", "", "a,b,c");
	CHECK_FILTER("a,b,c", "a", "b,c");
	CHECK_FILTER("a,b,c", "b", "a,c");
	CHECK_FILTER("a,b,c", "c", "a,b");
	CHECK_FILTER("a,b,c", "a,b", "c");
	CHECK_FILTER("a,b,c", "a,c", "b");
	CHECK_FILTER("a,b,c", "b,c", "a");
	CHECK_FILTER("a,b,c", "a,b,c", "");
	CHECK_FILTER("a,b,c", "b,c", "a");
	CHECK_FILTER("", "a,b,c", "");
	TEST_పూర్తి();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
