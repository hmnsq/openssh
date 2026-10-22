/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"

ശൂന്യം test_argv(ശൂന്യം);

ശൂന്യം
test_argv(ശൂന്യം)
{
	അക്ഷരം **av = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ac = 0;

#define RESET_ARGV() \
	ചെയ്യുക { \
		argv_free(av, ac); \
		av = ശൂന്യ; \
		ac = -1; \
	} ആകുമ്പോൾ (0)

	TEST_START("empty args");
	ASSERT_INT_EQ(argv_split("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_PTR_EQ(av[0], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_PTR_EQ(av[0], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("trivial args");
	ASSERT_INT_EQ(argv_split("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted");
	ASSERT_INT_EQ(argv_split("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("escaped");
	ASSERT_INT_EQ(argv_split("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted escaped");
	ASSERT_INT_EQ(argv_split("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("comments");
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_PTR_EQ(av[0], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ശൂന്യ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ശൂന്യ);
	RESET_ARGV();
	TEST_DONE();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
