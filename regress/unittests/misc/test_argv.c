/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"

શૂન્ય test_argv(શૂન્ય);

શૂન્ય
test_argv(શૂન્ય)
{
	અક્ષર **av = ખાલી;
	પૂર્ણાંક ac = 0;

#define RESET_ARGV() \
	કરો { \
		argv_free(av, ac); \
		av = ખાલી; \
		ac = -1; \
	} જ્યારે (0)

	TEST_START("empty args");
	ASSERT_INT_EQ(argv_split("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_PTR_EQ(av[0], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_PTR_EQ(av[0], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("trivial args");
	ASSERT_INT_EQ(argv_split("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted");
	ASSERT_INT_EQ(argv_split("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("escaped");
	ASSERT_INT_EQ(argv_split("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted escaped");
	ASSERT_INT_EQ(argv_split("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("comments");
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_PTR_EQ(av[0], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ખાલી);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ખાલી);
	RESET_ARGV();
	TEST_DONE();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
