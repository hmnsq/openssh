/* 	$OpenBSD: test_argv.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for misc argv handling functions.
 *
 * Placed in the public domain.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"

శూన్య test_argv(శూన్య);

శూన్య
test_argv(శూన్య)
{
	అక్షరం **av = ఖాళీ;
	పూర్ణాంకం ac = 0;

#నిర్వచించు RESET_ARGV() \
	చేయి { \
		argv_free(av, ac); \
		av = ఖాళీ; \
		ac = -1; \
	} అయితే (0)

	TEST_ప్రారంభం("empty args");
	ASSERT_INT_EQ(argv_విభజించు("", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_PTR_EQ(av[0], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("    ", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_PTR_EQ(av[0], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	TEST_ప్రారంభం("trivial args");
	ASSERT_INT_EQ(argv_విభజించు("leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("smiley leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_STRING_EQ(av[1], "leamas");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted");
	ASSERT_INT_EQ(argv_విభజించు("\"smiley\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("leamas \" smiley \"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas");
	ASSERT_STRING_EQ(av[1], " smiley ");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("\"smiley leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("smiley\" leamas\" liz", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_STRING_EQ(av[1], "liz");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	TEST_ప్రారంభం("escaped");
	ASSERT_INT_EQ(argv_విభజించు("\\\"smiley\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "\"smiley'");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("'\\'smiley\\\"'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "'smiley\"");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("smiley\\'s leamas\\'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley's");
	ASSERT_STRING_EQ(av[1], "leamas'");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("leamas\\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas\\smiley");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("leamas\\\\ \\\\smiley", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas\\");
	ASSERT_STRING_EQ(av[1], "\\smiley");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("smiley\\ leamas", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley leamas");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	TEST_ప్రారంభం("quoted escaped");
	ASSERT_INT_EQ(argv_విభజించు("'smiley\\ leamas'", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("\"smiley\\ leamas\"", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "smiley\\ leamas");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	TEST_ప్రారంభం("comments");
	ASSERT_INT_EQ(argv_విభజించు("# gold", &ac, &av, 0), 0);
	ASSERT_INT_EQ(ac, 2);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "#");
	ASSERT_STRING_EQ(av[1], "gold");
	ASSERT_PTR_EQ(av[2], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("# gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 0);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_PTR_EQ(av[0], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("leamas#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("\"leamas # gold\"", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas # gold");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	ASSERT_INT_EQ(argv_విభజించు("\"leamas\"#gold", &ac, &av, 1), 0);
	ASSERT_INT_EQ(ac, 1);
	ASSERT_PTR_NE(av, ఖాళీ);
	ASSERT_STRING_EQ(av[0], "leamas#gold");
	ASSERT_PTR_EQ(av[1], ఖాళీ);
	RESET_ARGV();
	TEST_పూర్తి();

	/* XXX test char *argv_assemble(int argc, char **argv) */
}
