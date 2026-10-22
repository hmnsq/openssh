/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_ਨਮੂਨਾ_original(ਅਚਲ ਅੱਖਰ *s, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	ਲਈ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ਜੇ (!*ਨਮੂਨਾ)
			ਵਾਪਸ !*s;

		ਜੇ (*ਨਮੂਨਾ == '*') {
			/* Skip this and any consecutive asterisks. */
			ਜਦੋਂ (*ਨਮੂਨਾ == '*')
				ਨਮੂਨਾ++;

			/* If at end of pattern, accept immediately. */
			ਜੇ (!*ਨਮੂਨਾ)
				ਵਾਪਸ 1;

			/* If next character in pattern is known, optimize. */
			ਜੇ (*ਨਮੂਨਾ != '?' && *ਨਮੂਨਾ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ਲਈ (; *s; s++)
					ਜੇ (*s == *ਨਮੂਨਾ &&
					    ਮੇਲ_ਨਮੂਨਾ_original(s + 1,
					    ਨਮੂਨਾ + 1))
						ਵਾਪਸ 1;
				/* Failed. */
				ਵਾਪਸ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ਲਈ (; *s; s++)
				ਜੇ (ਮੇਲ_ਨਮੂਨਾ_original(s, ਨਮੂਨਾ))
					ਵਾਪਸ 1;
			/* Failed. */
			ਵਾਪਸ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ਜੇ (!*s)
			ਵਾਪਸ 0;

		/* Check if the next character of the string is acceptable. */
		ਜੇ (*ਨਮੂਨਾ != '?' && *ਨਮੂਨਾ != *s)
			ਵਾਪਸ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		ਨਮੂਨਾ++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ਸਥਿਰ ਮਾਪ_t
pow_ਮਾਪ(ਮਾਪ_t ਅਧਾਰ, ਮਾਪ_t ਘਾਤਾਂਕ)
{
	ਮਾਪ_t r = 1;

	ASSERT_ਮਾਪ_T_NE(ਅਧਾਰ, 0);
	ਜਦੋਂ (ਘਾਤਾਂਕ-- != 0) {
		ASSERT_ਮਾਪ_T_LE(r, SIZE_MAX / ਅਧਾਰ);
		r *= ਅਧਾਰ;
	}
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
make_ਸ਼ਬਦ(ਮਾਪ_t v, ਅਚਲ ਅੱਖਰ *alphabet, ਮਾਪ_t alphabet_len,
    ਅੱਖਰ *ਸ਼ਬਦ_2, ਮਾਪ_t wordlen)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < wordlen; i++) {
		ਸ਼ਬਦ_2[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	ਸ਼ਬਦ_2[wordlen] = '\0';
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨਮੂਨਾ_LEN	8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਨਿਵੇਸ਼_LEN	7

ਸਥਿਰ ਖਾਲੀ
ਮੇਲ_ਨਮੂਨਾ_check_one_ਨਿਵੇਸ਼(ਅਚਲ ਅੱਖਰ *ਨਿਵੇਸ਼, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ_alphabet)
{
	ਅੱਖਰ ਨਮੂਨਾ[ਨਮੂਨਾ_LEN];
	ਮਾਪ_t len, i, npatterns;
	ਪੂਰਨ actual, expected;

	ਲਈ (len = 0; len < ਆਕਾਰ(ਨਮੂਨਾ); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_ਮਾਪ(ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ_alphabet), len);
		ਲਈ (i = 0; i < npatterns; i++) {
			make_ਸ਼ਬਦ(i, ਨਮੂਨਾ_alphabet,
			    ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ_alphabet), ਨਮੂਨਾ, len);
			actual = ਮੇਲ_ਨਮੂਨਾ(ਨਿਵੇਸ਼, ਨਮੂਨਾ);
			expected = ਮੇਲ_ਨਮੂਨਾ_original(ਨਿਵੇਸ਼, ਨਮੂਨਾ);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    ਨਿਵੇਸ਼, ਨਮੂਨਾ);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ਸਥਿਰ ਖਾਲੀ
ਮੇਲ_ਨਮੂਨਾ_exhaustive_original(ਖਾਲੀ)
{
	ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ_alphabet = "abx?*";
	ਅਚਲ ਅੱਖਰ *ਨਿਵੇਸ਼_alphabet = "abc";
	ਅੱਖਰ ਨਿਵੇਸ਼[ਨਿਵੇਸ਼_LEN];
	ਮਾਪ_t len, i, ninputs;

	ਲਈ (len = 0; len < ਆਕਾਰ(ਨਿਵੇਸ਼); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_ਮਾਪ(ਲੜੀ_ਲੰਬਾਈ(ਨਿਵੇਸ਼_alphabet), len);
		ਲਈ (i = 0; i < ninputs; i++) {
			make_ਸ਼ਬਦ(i, ਨਿਵੇਸ਼_alphabet,
			    ਲੜੀ_ਲੰਬਾਈ(ਨਿਵੇਸ਼_alphabet), ਨਿਵੇਸ਼, len);
			ਮੇਲ_ਨਮੂਨਾ_check_one_ਨਿਵੇਸ਼(ਨਿਵੇਸ਼, ਨਮੂਨਾ_alphabet);
		}
	}
}

ਖਾਲੀ
tests(ਖਾਲੀ)
{
	TEST_ਸ਼ੁਰੂ("match_pattern");
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", ""), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "aaa"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aaa", ""), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "abc"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "abd"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "abcd"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abcd", "abc"), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("match_pattern wildcard");
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "**"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "***"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "*?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "?*"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("", "**a*"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("a", "?"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "a?"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("a", "*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "a*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "?*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "?a"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "*a"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ba", "a?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ba", "a*"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "?a"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "*a"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aa", "**"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "a***b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("axb", "a***b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("axxb", "a***b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ax", "a***b"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "*b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "*a*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "*a*b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "*a*c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a?c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "??c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "???"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a?d"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "???"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "ab*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "ab*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("a", "ab*"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "ab?"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "ab?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abcd", "ab?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "?bc"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "?b*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "?c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a*?c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ac", "a*?c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a?*c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ac", "a?*c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "?*c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ac", "?*c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("c", "?*c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "*?c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ac", "*?c"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("c", "*?c"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a?*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "a?*"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("a", "a?*"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abc", "a*?"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("ab", "a*?"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("a", "a*?"), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abb", "a*b"), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ("abbc", "a*b"), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("match_pattern exhaustive original");
	ਮੇਲ_ਨਮੂਨਾ_exhaustive_original();
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("match_pattern_list");
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "*", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "!*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "", 0), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "*", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("b", "!*,a", 0), -1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("match_pattern_list lowercase");
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(ਮੇਲ_ਨਮੂਨਾ_list("ABC", "abc", 1), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("addr_match_list");
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ਮੇਲ_list(ਨਿਰਾ, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list(ਨਿਰਾ, "*"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ਮੇਲ_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_ਪੂਰਾ();

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHECK_FILTER(string,filter,expected) \
	ਕਰੋ { \
		ਅੱਖਰ *ਨਤੀਜਾ = ਮੇਲ_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(ਨਤੀਜਾ, expected); \
		ਮੁਕਤ(ਨਤੀਜਾ); \
	} ਜਦੋਂ (0)

	TEST_ਸ਼ੁਰੂ("match_filter_list");
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
	TEST_ਪੂਰਾ();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
