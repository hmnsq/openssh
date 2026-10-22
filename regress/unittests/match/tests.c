/* 	$OpenBSD: tests.c,v 1.10 2026/05/31 04:20:58 djm Exp $ */
/*
 * Regress test for matching functions
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "match.h"

/* Original match_pattern() implementation; has bad worst-case behaviour */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_ನಮೂನೆ_original(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	ಗಾಗಿ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ಆದರೆ (!*ನಮೂನೆ)
			ಹಿಂತಿರುಗಿ !*s;

		ಆದರೆ (*ನಮೂನೆ == '*') {
			/* Skip this and any consecutive asterisks. */
			ಆಗ (*ನಮೂನೆ == '*')
				ನಮೂನೆ++;

			/* If at end of pattern, accept immediately. */
			ಆದರೆ (!*ನಮೂನೆ)
				ಹಿಂತಿರುಗಿ 1;

			/* If next character in pattern is known, optimize. */
			ಆದರೆ (*ನಮೂನೆ != '?' && *ನಮೂನೆ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ಗಾಗಿ (; *s; s++)
					ಆದರೆ (*s == *ನಮೂನೆ &&
					    ಹೊಂದಿಕೆ_ನಮೂನೆ_original(s + 1,
					    ನಮೂನೆ + 1))
						ಹಿಂತಿರುಗಿ 1;
				/* Failed. */
				ಹಿಂತಿರುಗಿ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ಗಾಗಿ (; *s; s++)
				ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_original(s, ನಮೂನೆ))
					ಹಿಂತಿರುಗಿ 1;
			/* Failed. */
			ಹಿಂತಿರುಗಿ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ಆದರೆ (!*s)
			ಹಿಂತಿರುಗಿ 0;

		/* Check if the next character of the string is acceptable. */
		ಆದರೆ (*ನಮೂನೆ != '?' && *ನಮೂನೆ != *s)
			ಹಿಂತಿರುಗಿ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		ನಮೂನೆ++;
	}
	/* NOTREACHED */
}

/* n^x for size_t */
ಸ್ಥಿರ ಗಾತ್ರ_t
pow_ಗಾತ್ರ(ಗಾತ್ರ_t ತಳ, ಗಾತ್ರ_t ಘಾತಾಂಕ)
{
	ಗಾತ್ರ_t r = 1;

	ASSERT_ಗಾತ್ರ_T_NE(ತಳ, 0);
	ಆಗ (ಘಾತಾಂಕ-- != 0) {
		ASSERT_ಗಾತ್ರ_T_LE(r, SIZE_MAX / ತಳ);
		r *= ತಳ;
	}
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
make_ಶಬ್ದ(ಗಾತ್ರ_t v, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alphabet, ಗಾತ್ರ_t alphabet_len,
    ಅಕ್ಷರ *ಶಬ್ದ, ಗಾತ್ರ_t wordlen)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < wordlen; i++) {
		ಶಬ್ದ[i] = alphabet[v % alphabet_len];
		v /= alphabet_len;
	}
	ಶಬ್ದ[wordlen] = '\0';
}

#ವ್ಯಾಖ್ಯಾನಿಸು ನಮೂನೆ_LEN	8
#ವ್ಯಾಖ್ಯಾನಿಸು ಒಳಹರಿವು_LEN	7

ಸ್ಥಿರ ಶೂನ್ಯ
ಹೊಂದಿಕೆ_ನಮೂನೆ_check_one_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಒಳಹರಿವು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ_alphabet)
{
	ಅಕ್ಷರ ನಮೂನೆ[ನಮೂನೆ_LEN];
	ಗಾತ್ರ_t len, i, npatterns;
	ಪೂರ್ಣಾಂಕ actual, expected;

	ಗಾಗಿ (len = 0; len < ಗಾತ್ರ(ನಮೂನೆ); len++) {
		/* Check with all patterns of this size using alphabet */
		npatterns = pow_ಗಾತ್ರ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ_alphabet), len);
		ಗಾಗಿ (i = 0; i < npatterns; i++) {
			make_ಶಬ್ದ(i, ನಮೂನೆ_alphabet,
			    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ_alphabet), ನಮೂನೆ, len);
			actual = ಹೊಂದಿಕೆ_ನಮೂನೆ(ಒಳಹರಿವು, ನಮೂನೆ);
			expected = ಹೊಂದಿಕೆ_ನಮೂನೆ_original(ಒಳಹರಿವು, ನಮೂನೆ);
			test_subtest_info("input=\"%s\" pattern=\"%s\"",
			    ಒಳಹರಿವು, ನಮೂನೆ);
			ASSERT_INT_EQ(actual, expected);
		}
	}
}

/*
 * Check current match_pattern against original one with an exhaustive
 * combination of patterns and inputs.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
ಹೊಂದಿಕೆ_ನಮೂನೆ_exhaustive_original(ಶೂನ್ಯ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ_alphabet = "abx?*";
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಒಳಹರಿವು_alphabet = "abc";
	ಅಕ್ಷರ ಒಳಹರಿವು[ಒಳಹರಿವು_LEN];
	ಗಾತ್ರ_t len, i, ninputs;

	ಗಾಗಿ (len = 0; len < ಗಾತ್ರ(ಒಳಹರಿವು); len++) {
		/* Check every possible input from alphabet of this size */
		ninputs = pow_ಗಾತ್ರ(ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಒಳಹರಿವು_alphabet), len);
		ಗಾಗಿ (i = 0; i < ninputs; i++) {
			make_ಶಬ್ದ(i, ಒಳಹರಿವು_alphabet,
			    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಒಳಹರಿವು_alphabet), ಒಳಹರಿವು, len);
			ಹೊಂದಿಕೆ_ನಮೂನೆ_check_one_ಒಳಹರಿವು(ಒಳಹರಿವು, ನಮೂನೆ_alphabet);
		}
	}
}

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
	TEST_ಆರಂಭ("match_pattern");
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", ""), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "aaa"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aaa", ""), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aaa", "aaaa"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aaaa", "aaa"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "abc"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "abd"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "abcd"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abcd", "abc"), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("match_pattern wildcard");
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "**"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "***"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "*?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "?*"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("", "**a*"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("a", "?"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "a?"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("a", "*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "a*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "?*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "?a"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "*a"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ba", "a?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ba", "a*"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "?a"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "*a"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aa", "**"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "a***b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("axb", "a***b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("axxb", "a***b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ax", "a***b"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abbb", "a*b*b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abbb", "a*b*c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aaaaaaaaac", "a*a*a*a*b"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("aaaaaaaaab", "a*a*a*a*b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "*b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "*a*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "*a*b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "*a*c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a?c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "??c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "???"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a?d"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "???"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "ab*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "ab*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("a", "ab*"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "ab?"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "ab?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abcd", "ab?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "?bc"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "?b*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "?c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a*?c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ac", "a*?c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abbc", "a*?c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a?*c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ac", "a?*c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abbc", "a?*c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a*?*c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ac", "a*?*c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "?*c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ac", "?*c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("c", "?*c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "*?c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ac", "*?c"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("c", "*?c"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a?*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "a?*"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("a", "a?*"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abc", "a*?"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("ab", "a*?"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("a", "a*?"), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abb", "a*b"), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ("abbc", "a*b"), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("match_pattern exhaustive original");
	ಹೊಂದಿಕೆ_ನಮೂನೆ_exhaustive_original();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("match_pattern_list");
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "", 0), 0); /* no patterns */
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "*", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "!*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "!a,*", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "*,!a", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "a,!*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("", "!*,a", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "", 0), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "*", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "!*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("a", "!b", 0), 1); */
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "!a,*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("b", "!a,*", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "*,!a", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("b", "*,!a", 0), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "a,!*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("b", "a,!*", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "a,!a", 0), -1);
	/* XXX negated ASSERT_INT_EQ(match_pattern_list("b", "a,!a", 0), 1); */
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("a", "!*,a", 0), -1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("b", "!*,a", 0), -1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("match_pattern_list lowercase");
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("abc", "ABC", 0), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("ABC", "abc", 0), 0);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("abc", "ABC", 1), 1);
	ASSERT_INT_EQ(ಹೊಂದಿಕೆ_ನಮೂನೆ_list("ABC", "abc", 1), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("addr_match_list");
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list(ಖಾಲಿ, "127.0.0.1/44"), -2);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("a", "*"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "*"), 1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list(ಖಾಲಿ, "*"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.0.1"), 1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "!127.0.0.1"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2"), 1); */
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.255", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.1.1", "127.0.0.0/24"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.0.0/24"), 1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.1.0/24"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "!127.0.0.0/24"), -1);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.1.0/24"), 1); */
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "10.0.0.1,!127.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "!127.0.0.1,10.0.0.1"), -1);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "10.0.0.1,127.0.0.2"), 0);
	ASSERT_INT_EQ(addr_ಹೊಂದಿಕೆ_list("127.0.0.1", "127.0.0.2,10.0.0.1"), 0);
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "10.0.0.1,!127.0.0.2"), 1); */
	/* XXX negated ASSERT_INT_EQ(addr_match_list("127.0.0.1", "!127.0.0.2,10.0.0.1"), 1); */
	TEST_ಮುಗಿದ();

#ವ್ಯಾಖ್ಯಾನಿಸು CHECK_FILTER(string,filter,expected) \
	ಮಾಡು { \
		ಅಕ್ಷರ *ಫಲಿತಾಂಶ = ಹೊಂದಿಕೆ_filter_denylist((string), (filter)); \
		ASSERT_STRING_EQ(ಫಲಿತಾಂಶ, expected); \
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ); \
	} ಆಗ (0)

	TEST_ಆರಂಭ("match_filter_list");
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
	TEST_ಮುಗಿದ();
/*
 * XXX TODO
 * int      match_host_and_ip(const char *, const char *, const char *);
 * int      match_user(const char *, const char *, const char *, const char *);
 * char    *match_list(const char *, const char *, u_int *);
 * int      addr_match_cidr_list(const char *, const char *);
 */
}

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	ಬರೆ("no benchmarks\n");
}
