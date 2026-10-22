/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
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

#অন্তর্ভাব "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
স্থির পূর্ণসংখ্যা
match_pattern_original(ধ্রুবক অক্ষর *s, ধ্রুবক অক্ষর *pattern)
{
	জন্য (;;) {
		/* If at end of pattern, accept if also at end of string. */
		যদি (!*pattern)
			ফেরত !*s;

		যদি (*pattern == '*') {
			/* Skip this and any consecutive asterisks. */
			যখন (*pattern == '*')
				pattern++;

			/* If at end of pattern, accept immediately. */
			যদি (!*pattern)
				ফেরত 1;

			/* If next character in pattern is known, optimize. */
			যদি (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				জন্য (; *s; s++)
					যদি (*s == *pattern &&
					    match_pattern_original(s + 1,
					    pattern + 1))
						ফেরত 1;
				/* Failed. */
				ফেরত 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			জন্য (; *s; s++)
				যদি (match_pattern_original(s, pattern))
					ফেরত 1;
			/* Failed. */
			ফেরত 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		যদি (!*s)
			ফেরত 0;

		/* Check if the next character of the string is acceptable. */
		যদি (*pattern != '?' && *pattern != *s)
			ফেরত 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
স্থির আকার_t
pow_আকার(আকার_t base, আকার_t exp)
{
	আকার_t r = 1;

	ASSERT_আকার_T_NE(base, 0);
	যখন (exp-- != 0) {
		ASSERT_আকার_T_LE(r, SIZE_MAX / base);
		r *= base;
	}
	ফেরত r;
}

স্থির শূন্য
make_word(আকার_t v, ধ্রুবক অক্ষর *alphabet, আকার_t alphabet_len,
    অক্ষর *word, আকার_t wordlen)
{
	আকার_t i;

	জন্য (i = 0; i < wordlen; i++) {
		word[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	word[wordlen] = '\0';
}

#define PATTERN_LEN	8
#define প্রবেশ_LEN	7

স্থির শূন্য
match_pattern_check_one_প্রবেশ(ধ্রুবক অক্ষর *প্রবেশ, ধ্রুবক অক্ষর *pattern_alphabet)
{
	অক্ষর pattern[PATTERN_LEN];
	আকার_t len, i, npatterns;
	পূর্ণসংখ্যা actual, expected;

	জন্য (len = 0; len < আকার(pattern); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_আকার(strlen(pattern_alphabet), len);
		জন্য (i = 0; i < npatterns; i++) {
			make_word(i, pattern_alphabet,
			    strlen(pattern_alphabet), pattern, len);
			actual = match_pattern(প্রবেশ, pattern);
			expected = match_pattern_original(প্রবেশ, pattern);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    প্রবেশ, pattern);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
স্থির শূন্য
match_pattern_exhaustive_original(শূন্য)
{
	ধ্রুবক অক্ষর *pattern_alphabet = "abx?*";
	ধ্রুবক অক্ষর *প্রবেশ_alphabet = "abc";
	অক্ষর প্রবেশ[প্রবেশ_LEN];
	আকার_t len, i, ninputs;

	জন্য (len = 0; len < আকার(প্রবেশ); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_আকার(strlen(প্রবেশ_alphabet), len);
		জন্য (i = 0; i < ninputs; i++) {
			make_word(i, প্রবেশ_alphabet,
			    strlen(প্রবেশ_alphabet), প্রবেশ, len);
			match_pattern_check_one_প্রবেশ(প্রবেশ, pattern_alphabet);
		}
	}
}

শূন্য
tests(শূন্য)
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
	ASSERT_INT_EQ(addr_match_list(ফাঁকা, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_match_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_match_list(ফাঁকা, "*"), 0);
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
	করো { \
		অক্ষর *ফলাফল = match_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(ফলাফল, expected); \
		মুক্ত(ফলাফল); \
	} যখন (0)

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

শূন্য
benchmarks(শূন্য)
{
	printf("no benchmarks\n");
}
