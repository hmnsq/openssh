/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

ಶೂನ್ಯ test_argv(ಶೂನ್ಯ);

ಶೂನ್ಯ
test_argv(ಶೂನ್ಯ)
{
	ವರ್ಣ **av = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ac = 0;

#define RESET_ARGV() \
	ಕುರು { \
		argv_free(av, ac); \
		av = ರಿಕ್ತ; \
		ac = -1; \
	} ಯಾವತ್ (0)

	TEST_START("empty args");
	ASSERT_INT_EQ(argv_split("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_PTR_EQ(av[0], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_PTR_EQ(av[0], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("trivial args");
	ASSERT_INT_EQ(argv_split("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted");
	ASSERT_INT_EQ(argv_split("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("escaped");
	ASSERT_INT_EQ(argv_split("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted escaped");
	ASSERT_INT_EQ(argv_split("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("comments");
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_PTR_EQ(av[0], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ರಿಕ್ತ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ರಿಕ್ತ);
	RESET_ARGV();
	TEST_DONE();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
