/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
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

#અન્તર્ભાવ "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
સ્થિર પૂર્ણાંક
match_pattern_original(અચલ અક્ષર *s, અચલ અક્ષર *pattern)
{
	માટે (;;) {
		/* If at end of pattern, accept if also at end of string. */
		જો (!*pattern)
			પાછા !*s;

		જો (*pattern == '*') {
			/* Skip this and any consecutive asterisks. */
			જ્યારે (*pattern == '*')
				pattern++;

			/* If at end of pattern, accept immediately. */
			જો (!*pattern)
				પાછા 1;

			/* If next character in pattern is known, optimize. */
			જો (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				માટે (; *s; s++)
					જો (*s == *pattern &&
					    match_pattern_original(s + 1,
					    pattern + 1))
						પાછા 1;
				/* Failed. */
				પાછા 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			માટે (; *s; s++)
				જો (match_pattern_original(s, pattern))
					પાછા 1;
			/* Failed. */
			પાછા 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		જો (!*s)
			પાછા 0;

		/* Check if the next character of the string is acceptable. */
		જો (*pattern != '?' && *pattern != *s)
			પાછા 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
સ્થિર size_t
pow_size(size_t base, size_t exp)
{
	size_t r = 1;

	ASSERT_SIZE_T_NE(base, 0);
	જ્યારે (exp-- != 0) {
		ASSERT_SIZE_T_LE(r, SIZE_MAX / base);
		r *= base;
	}
	પાછા r;
}

સ્થિર શૂન્ય
make_word(size_t v, અચલ અક્ષર *alphabet, size_t alphabet_len,
    અક્ષર *word, size_t wordlen)
{
	size_t i;

	માટે (i = 0; i < wordlen; i++) {
		word[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	word[wordlen] = '\0';
}

#define PATTERN_LEN	8
#define આગત_LEN	7

સ્થિર શૂન્ય
match_pattern_check_one_આગત(અચલ અક્ષર *આગત, અચલ અક્ષર *pattern_alphabet)
{
	અક્ષર pattern[PATTERN_LEN];
	size_t len, i, npatterns;
	પૂર્ણાંક actual, expected;

	માટે (len = 0; len < કદ(pattern); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_size(strlen(pattern_alphabet), len);
		માટે (i = 0; i < npatterns; i++) {
			make_word(i, pattern_alphabet,
			    strlen(pattern_alphabet), pattern, len);
			actual = match_pattern(આગત, pattern);
			expected = match_pattern_original(આગત, pattern);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    આગત, pattern);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
સ્થિર શૂન્ય
match_pattern_exhaustive_original(શૂન્ય)
{
	અચલ અક્ષર *pattern_alphabet = "abx?*";
	અચલ અક્ષર *આગત_alphabet = "abc";
	અક્ષર આગત[આગત_LEN];
	size_t len, i, ninputs;

	માટે (len = 0; len < કદ(આગત); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_size(strlen(આગત_alphabet), len);
		માટે (i = 0; i < ninputs; i++) {
			make_word(i, આગત_alphabet,
			    strlen(આગત_alphabet), આગત, len);
			match_pattern_check_one_આગત(આગત, pattern_alphabet);
		}
	}
}

શૂન્ય
tests(શૂન્ય)
{
	TEST_START("match_pattern");
	ASSERT_INT_EQ(match_pattern("", ""), 1);
	ASSERT_INT_EQ(match_pattern("", "aaa"), 0);
	ASSERT_INT_EQ(match_pattern("aaa", ""), 0);
	ASSERT_INT_EQ(match_pattern("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(match_pattern("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "abc"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "abd"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "abcd"), 0);
	ASSERT_INT_EQ(match_pattern("abcd", "abc"), 0);
	TEST_DONE();

	TEST_START("match_pattern wildcard");
	ASSERT_INT_EQ(match_pattern("", "*"), 1);
	ASSERT_INT_EQ(match_pattern("", "**"), 1);
	ASSERT_INT_EQ(match_pattern("", "***"), 1);
	ASSERT_INT_EQ(match_pattern("", "?"), 0);
	ASSERT_INT_EQ(match_pattern("", "*?"), 0);
	ASSERT_INT_EQ(match_pattern("", "?*"), 0);
	ASSERT_INT_EQ(match_pattern("", "**a*"), 0);
	ASSERT_INT_EQ(match_pattern("a", "?"), 1);
	ASSERT_INT_EQ(match_pattern("aa", "a?"), 1);
	ASSERT_INT_EQ(match_pattern("a", "*"), 1);
	ASSERT_INT_EQ(match_pattern("aa", "a*"), 1);
	ASSERT_INT_EQ(match_pattern("aa", "?*"), 1);
	ASSERT_INT_EQ(match_pattern("aa", "?a"), 1);
	ASSERT_INT_EQ(match_pattern("aa", "*a"), 1);
	ASSERT_INT_EQ(match_pattern("ba", "a?"), 0);
	ASSERT_INT_EQ(match_pattern("ba", "a*"), 0);
	ASSERT_INT_EQ(match_pattern("ab", "?a"), 0);
	ASSERT_INT_EQ(match_pattern("ab", "*a"), 0);
	ASSERT_INT_EQ(match_pattern("aa", "**"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "a***b"), 1);
	ASSERT_INT_EQ(match_pattern("axb", "a***b"), 1);
	ASSERT_INT_EQ(match_pattern("axxb", "a***b"), 1);
	ASSERT_INT_EQ(match_pattern("ax", "a***b"), 0);
	ASSERT_INT_EQ(match_pattern("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(match_pattern("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(match_pattern("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(match_pattern("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "*b"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "*a*"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "*a*b"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "*a*c"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "a?c"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "??c"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "???"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "a?d"), 0);
	ASSERT_INT_EQ(match_pattern("ab", "???"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "ab*"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "ab*"), 1);
	ASSERT_INT_EQ(match_pattern("a", "ab*"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "ab?"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "ab?"), 0);
	ASSERT_INT_EQ(match_pattern("abcd", "ab?"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "?bc"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "?b*"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "?c"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "a*?c"), 1);
	ASSERT_INT_EQ(match_pattern("ac", "a*?c"), 0);
	ASSERT_INT_EQ(match_pattern("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "a?*c"), 1);
	ASSERT_INT_EQ(match_pattern("ac", "a?*c"), 0);
	ASSERT_INT_EQ(match_pattern("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(match_pattern("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(match_pattern("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "?*c"), 1);
	ASSERT_INT_EQ(match_pattern("ac", "?*c"), 1);
	ASSERT_INT_EQ(match_pattern("c", "?*c"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "*?c"), 1);
	ASSERT_INT_EQ(match_pattern("ac", "*?c"), 1);
	ASSERT_INT_EQ(match_pattern("c", "*?c"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "a?*"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "a?*"), 1);
	ASSERT_INT_EQ(match_pattern("a", "a?*"), 0);
	ASSERT_INT_EQ(match_pattern("abc", "a*?"), 1);
	ASSERT_INT_EQ(match_pattern("ab", "a*?"), 1);
	ASSERT_INT_EQ(match_pattern("a", "a*?"), 0);
	ASSERT_INT_EQ(match_pattern("abb", "a*b"), 1);
	ASSERT_INT_EQ(match_pattern("abbc", "a*b"), 0);
	TEST_DONE();

	TEST_START("match_pattern exhaustive original");
	match_pattern_exhaustive_original();
	TEST_DONE();

	TEST_START("match_pattern_list");
	ASSERT_INT_EQ(match_pattern_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(match_pattern_list("", "*", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("", "!*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("a", "", 0), 0);
	ASSERT_INT_EQ(match_pattern_list("a", "*", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(match_pattern_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(match_pattern_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(match_pattern_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(match_pattern_list("b", "!*,a", 0), -1);
	TEST_DONE();

	TEST_START("match_pattern_list lowercase");
	ASSERT_INT_EQ(match_pattern_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(match_pattern_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(match_pattern_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(match_pattern_list("ABC", "abc", 1), 0);
	TEST_DONE();

	TEST_START("addr_match_list");
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_match_list(ખાલી, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_match_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_match_list(ખાલી, "*"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_match_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_match_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_DONE();

#define CHECK_FILTER(string,filter,expected) \
	કરો { \
		અક્ષર *result = match_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(result, expected); \
		મુક્ત(result); \
	} જ્યારે (0)

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
	TEST_DONE();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
