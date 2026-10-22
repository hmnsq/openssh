/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"

வெறுமை test_argv(வெறுமை);

வெறுமை
test_argv(வெறுமை)
{
	எழுத்து **av = வெற்று;
	முழு ac = 0;

#define RESET_ARGV() \
	செய் { \
		argv_free(av, ac); \
		av = வெற்று; \
		ac = -1; \
	} போது (0)

	TEST_START("empty args");
	ASSERT_INT_EQ(argv_split("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_PTR_EQ(av[0], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_PTR_EQ(av[0], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("trivial args");
	ASSERT_INT_EQ(argv_split("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted");
	ASSERT_INT_EQ(argv_split("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("escaped");
	ASSERT_INT_EQ(argv_split("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("quoted escaped");
	ASSERT_INT_EQ(argv_split("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	TEST_START("comments");
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_PTR_EQ(av[0], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_split("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, வெற்று);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], வெற்று);
	RESET_ARGV();
	TEST_DONE();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
