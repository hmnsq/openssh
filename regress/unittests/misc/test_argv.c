/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "log.h"
#ضمن "misc.h"

فراغ test_argv(فراغ);

فراغ
test_argv(فراغ)
{
	حرف **av = عدم;
	صحيح ac = 0;

#وصف_ڪريو RESET_ARGV() \
	افعل { \
		argv_free(av, ac); \
		av = عدم; \
		ac = -1; \
	} طالما (0)

	TEST_شروعات("empty args");
	ASSERT_INT_EQ(argv_ورهايو("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_PTR_EQ(av[0], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_PTR_EQ(av[0], عدم);
	RESET_ARGV();
	TEST_پورو();

	TEST_شروعات("trivial args");
	ASSERT_INT_EQ(argv_ورهايو("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	TEST_پورو();

	TEST_شروعات("quoted");
	ASSERT_INT_EQ(argv_ورهايو("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	TEST_پورو();

	TEST_شروعات("escaped");
	ASSERT_INT_EQ(argv_ورهايو("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	TEST_پورو();

	TEST_شروعات("quoted escaped");
	ASSERT_INT_EQ(argv_ورهايو("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	TEST_پورو();

	TEST_شروعات("comments");
	ASSERT_INT_EQ(argv_ورهايو("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_PTR_EQ(av[0], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_ورهايو("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, عدم);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], عدم);
	RESET_ARGV();
	TEST_پورو();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
