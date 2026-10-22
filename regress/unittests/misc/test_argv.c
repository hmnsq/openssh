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
	ಅಕ್ಷರ **av = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ac = 0;

#ವ್ಯಾಖ್ಯಾನಿಸು RESET_ARGV() \
	ಮಾಡು { \
		argv_free(av, ac); \
		av = ಖಾಲಿ; \
		ac = -1; \
	} ಆಗ (0)

	TEST_ಆರಂಭ("empty args");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_PTR_EQ(av[0], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_PTR_EQ(av[0], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("trivial args");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("escaped");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("quoted escaped");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("comments");
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_PTR_EQ(av[0], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ವಿಭಜಿಸು("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ಖಾಲಿ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ಖಾಲಿ);
	RESET_ARGV();
	TEST_ಮುಗಿದ();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
