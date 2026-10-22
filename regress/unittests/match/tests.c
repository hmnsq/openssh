/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
நிலையான முழு
match_pattern_original(மாறிலி எழுத்து *s, மாறிலி எழுத்து *pattern)
{
	க்கு (;;) {
		/* If at end of pattern, accept if also at end of string. */
		எனில் (!*pattern)
			திரும்பு !*s;

		எனில் (*pattern == '*') {
			/* Skip this and any consecutive asterisks. */
			போது (*pattern == '*')
				pattern++;

			/* If at end of pattern, accept immediately. */
			எனில் (!*pattern)
				திரும்பு 1;

			/* If next character in pattern is known, optimize. */
			எனில் (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				க்கு (; *s; s++)
					எனில் (*s == *pattern &&
					    match_pattern_original(s + 1,
					    pattern + 1))
						திரும்பு 1;
				/* Failed. */
				திரும்பு 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			க்கு (; *s; s++)
				எனில் (match_pattern_original(s, pattern))
					திரும்பு 1;
			/* Failed. */
			திரும்பு 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		எனில் (!*s)
			திரும்பு 0;

		/* Check if the next character of the string is acceptable. */
		எனில் (*pattern != '?' && *pattern != *s)
			திரும்பு 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
நிலையான size_t
pow_size(size_t base, size_t exp)
{
	size_t r = 1;

	ASSERT_SIZE_T_NE(base, 0);
	போது (exp-- != 0) {
		ASSERT_SIZE_T_LE(r, SIZE_MAX / base);
		r *= base;
	}
	திரும்பு r;
}

நிலையான வெறுமை
make_word(size_t v, மாறிலி எழுத்து *alphabet, size_t alphabet_len,
    எழுத்து *word, size_t wordlen)
{
	size_t i;

	க்கு (i = 0; i < wordlen; i++) {
		word[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	word[wordlen] = '\0';
}

#define PATTERN_LEN	8
#define உள்ளீடு_LEN	7

நிலையான வெறுமை
match_pattern_check_one_உள்ளீடு(மாறிலி எழுத்து *உள்ளீடு, மாறிலி எழுத்து *pattern_alphabet)
{
	எழுத்து pattern[PATTERN_LEN];
	size_t len, i, npatterns;
	முழு actual, expected;

	க்கு (len = 0; len < அளவு(pattern); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_size(strlen(pattern_alphabet), len);
		க்கு (i = 0; i < npatterns; i++) {
			make_word(i, pattern_alphabet,
			    strlen(pattern_alphabet), pattern, len);
			actual = match_pattern(உள்ளீடு, pattern);
			expected = match_pattern_original(உள்ளீடு, pattern);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    உள்ளீடு, pattern);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
நிலையான வெறுமை
match_pattern_exhaustive_original(வெறுமை)
{
	மாறிலி எழுத்து *pattern_alphabet = "abx?*";
	மாறிலி எழுத்து *உள்ளீடு_alphabet = "abc";
	எழுத்து உள்ளீடு[உள்ளீடு_LEN];
	size_t len, i, ninputs;

	க்கு (len = 0; len < அளவு(உள்ளீடு); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_size(strlen(உள்ளீடு_alphabet), len);
		க்கு (i = 0; i < ninputs; i++) {
			make_word(i, உள்ளீடு_alphabet,
			    strlen(உள்ளீடு_alphabet), உள்ளீடு, len);
			match_pattern_check_one_உள்ளீடு(உள்ளீடு, pattern_alphabet);
		}
	}
}

வெறுமை
tests(வெறுமை)
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
	ASSERT_INT_EQ(addr_match_list(வெற்று, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_match_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_match_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_match_list(வெற்று, "*"), 0);
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
	செய் { \
		எழுத்து *result = match_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(result, expected); \
		விடுவி(result); \
	} போது (0)

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

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
