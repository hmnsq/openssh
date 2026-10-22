/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "log.h"
#شامل "misc.h"

خالی test_argv(خالی);

خالی
test_argv(خالی)
{
	حرف **av = تہی;
	صحیح ac = 0;

#تعریف_کرو RESET_ARGV() \
	کرو { \
		argv_free(av, ac); \
		av = تہی; \
		ac = -1; \
	} جب (0)

	TEST_آغاز("empty args");
	ASSERT_INT_EQ(argv_بانٹو("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_PTR_EQ(av[0], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_PTR_EQ(av[0], تہی);
	RESET_ARGV();
	TEST_مکمل();

	TEST_آغاز("trivial args");
	ASSERT_INT_EQ(argv_بانٹو("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	TEST_مکمل();

	TEST_آغاز("quoted");
	ASSERT_INT_EQ(argv_بانٹو("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	TEST_مکمل();

	TEST_آغاز("escaped");
	ASSERT_INT_EQ(argv_بانٹو("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	TEST_مکمل();

	TEST_آغاز("quoted escaped");
	ASSERT_INT_EQ(argv_بانٹو("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	TEST_مکمل();

	TEST_آغاز("comments");
	ASSERT_INT_EQ(argv_بانٹو("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_PTR_EQ(av[0], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_بانٹو("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, تہی);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], تہی);
	RESET_ARGV();
	TEST_مکمل();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
