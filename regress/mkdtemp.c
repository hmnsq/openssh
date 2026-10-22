/*
 * Copyright (c) 2017 Colin Watson <cjwatson@debian.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Roughly equivalent to "mktemp -d -t TEMPLATE", but portable. */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

स्थिर शून्य
usage(शून्य)
{
	ख_लिखो(मानक_त्रुटि, "mkdtemp template\n");
	निकास(1);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	स्थिरांक अक्षर *base;
	स्थिरांक अक्षर *tmpdir;
	अक्षर ढाँचा[PATH_MAX];
	पूर्णांक r;
	अक्षर *dir;

	जर (argc != 2)
		usage();
	base = argv[1];

	जर ((tmpdir = दो_पर्या("TMPDIR")) == रिक्त)
		tmpdir = "/tmp";
	r = snprintf(ढाँचा, आकार(ढाँचा), "%s/%s", tmpdir, base);
	जर (r < 0 || (माप_प्रकार)r >= आकार(ढाँचा))
		fatal("template string too long");
	dir = mkdtemp(ढाँचा);
	जर (dir == रिक्त) {
		लिखो_त्रुटि("mkdtemp");
		निकास(1);
	}
	माला_दो(dir);
	परत 0;
}
