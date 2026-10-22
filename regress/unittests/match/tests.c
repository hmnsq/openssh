/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
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

#अन्तर्भाव "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
स्थिर पूर्णाङ्क
मेलनम्_आदर्शः_original(ध्रुव वर्ण *s, ध्रुव वर्ण *आदर्शः)
{
	प्रति (;;) {
		/* If at end of pattern, accept if also at end of string. */
		यदि (!*आदर्शः)
			प्रत्यागम !*s;

		यदि (*आदर्शः == '*') {
			/* Skip this and any consecutive asterisks. */
			यावत् (*आदर्शः == '*')
				आदर्शः++;

			/* If at end of pattern, accept immediately. */
			यदि (!*आदर्शः)
				प्रत्यागम 1;

			/* If next character in pattern is known, optimize. */
			यदि (*आदर्शः != '?' && *आदर्शः != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				प्रति (; *s; s++)
					यदि (*s == *आदर्शः &&
					    मेलनम्_आदर्शः_original(s + 1,
					    आदर्शः + 1))
						प्रत्यागम 1;
				/* Failed. */
				प्रत्यागम 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			प्रति (; *s; s++)
				यदि (मेलनम्_आदर्शः_original(s, आदर्शः))
					प्रत्यागम 1;
			/* Failed. */
			प्रत्यागम 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		यदि (!*s)
			प्रत्यागम 0;

		/* Check if the next character of the string is acceptable. */
		यदि (*आदर्शः != '?' && *आदर्शः != *s)
			प्रत्यागम 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		आदर्शः++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
स्थिर आकार_t
pow_आकार(आकार_t आधारः, आकार_t घातांकः)
{
	आकार_t r = 1;

	ASSERT_आकार_T_NE(आधारः, 0);
	यावत् (घातांकः-- != 0) {
		ASSERT_आकार_T_LE(r, SIZE_MAX / आधारः);
		r *= आधारः;
	}
	प्रत्यागम r;
}

स्थिर शून्य
make_word(आकार_t v, ध्रुव वर्ण *alphabet, आकार_t alphabet_len,
    वर्ण *word, आकार_t wordlen)
{
	आकार_t i;

	प्रति (i = 0; i < wordlen; i++) {
		word[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	word[wordlen] = '\0';
}

#परिभाषय आदर्शः_LEN	8
#परिभाषय निवेशः_LEN	7

स्थिर शून्य
मेलनम्_आदर्शः_check_one_निवेशः(ध्रुव वर्ण *निवेशः, ध्रुव वर्ण *आदर्शः_alphabet)
{
	वर्ण आदर्शः[आदर्शः_LEN];
	आकार_t len, i, npatterns;
	पूर्णाङ्क actual, expected;

	प्रति (len = 0; len < परिमाण(आदर्शः); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_आकार(वाक्यदैर्घ्यम्(आदर्शः_alphabet), len);
		प्रति (i = 0; i < npatterns; i++) {
			make_word(i, आदर्शः_alphabet,
			    वाक्यदैर्घ्यम्(आदर्शः_alphabet), आदर्शः, len);
			actual = मेलनम्_आदर्शः(निवेशः, आदर्शः);
			expected = मेलनम्_आदर्शः_original(निवेशः, आदर्शः);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    निवेशः, आदर्शः);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
स्थिर शून्य
मेलनम्_आदर्शः_exhaustive_original(शून्य)
{
	ध्रुव वर्ण *आदर्शः_alphabet = "abx?*";
	ध्रुव वर्ण *निवेशः_alphabet = "abc";
	वर्ण निवेशः[निवेशः_LEN];
	आकार_t len, i, ninputs;

	प्रति (len = 0; len < परिमाण(निवेशः); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_आकार(वाक्यदैर्घ्यम्(निवेशः_alphabet), len);
		प्रति (i = 0; i < ninputs; i++) {
			make_word(i, निवेशः_alphabet,
			    वाक्यदैर्घ्यम्(निवेशः_alphabet), निवेशः, len);
			मेलनम्_आदर्शः_check_one_निवेशः(निवेशः, आदर्शः_alphabet);
		}
	}
}

शून्य
tests(शून्य)
{
	TEST_START("match_pattern");
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", ""), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "aaa"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aaa", ""), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "abc"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "abd"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "abcd"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abcd", "abc"), 0);
	TEST_समाप्तम्();

	TEST_START("match_pattern wildcard");
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "**"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "***"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "*?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "?*"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("", "**a*"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("a", "?"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "a?"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("a", "*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "a*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "?*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "?a"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "*a"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ba", "a?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ba", "a*"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "?a"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "*a"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aa", "**"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "a***b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("axb", "a***b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("axxb", "a***b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ax", "a***b"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "*b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "*a*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "*a*b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "*a*c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a?c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "??c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "???"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a?d"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "???"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "ab*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "ab*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("a", "ab*"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "ab?"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "ab?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abcd", "ab?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "?bc"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "?b*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "?c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a*?c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ac", "a*?c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a?*c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ac", "a?*c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "?*c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ac", "?*c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("c", "?*c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "*?c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ac", "*?c"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("c", "*?c"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a?*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "a?*"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("a", "a?*"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abc", "a*?"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("ab", "a*?"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("a", "a*?"), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abb", "a*b"), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः("abbc", "a*b"), 0);
	TEST_समाप्तम्();

	TEST_START("match_pattern exhaustive original");
	मेलनम्_आदर्शः_exhaustive_original();
	TEST_समाप्तम्();

	TEST_START("match_pattern_list");
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "*", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "!*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "", 0), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "*", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("b", "!*,a", 0), -1);
	TEST_समाप्तम्();

	TEST_START("match_pattern_list lowercase");
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(मेलनम्_आदर्शः_list("ABC", "abc", 1), 0);
	TEST_समाप्तम्();

	TEST_START("addr_match_list");
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_मेलनम्_list(रिक्त, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_मेलनम्_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_मेलनम्_list(रिक्त, "*"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_मेलनम्_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_समाप्तम्();

#परिभाषय CHECK_FILTER(string,filter,expected) \
	कुरु { \
		वर्ण *परिणाम = मेलनम्_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(परिणाम, expected); \
		मुक्त(परिणाम); \
	} यावत् (0)

	TEST_START("match_filter_list");
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
	TEST_समाप्तम्();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

शून्य
benchmarks(शून्य)
{
	प्रारूप_लिख("no benchmarks\n");
}
