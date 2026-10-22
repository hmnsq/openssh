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

#समावेश "includes.h"

#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <unistd.h>

#समावेश "log.h"

अटल व्योम
usage(व्योम)
{
	ख_लिखो(मानक_त्रुटि, "mkdtemp template\n");
	निकास(1);
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	स्थिर अक्षर *base;
	स्थिर अक्षर *tmpdir;
	अक्षर ढाँचा[PATH_MAX];
	पूर्णांक r;
	अक्षर *dir;

	अगर (argc != 2)
		usage();
	base = argv[1];

	अगर ((tmpdir = दो_पर्या("TMPDIR")) == शून्य)
		tmpdir = "/tmp";
	r = snprintf(ढाँचा, माप(ढाँचा), "%s/%s", tmpdir, base);
	अगर (r < 0 || (माप_प्रकार)r >= माप(ढाँचा))
		fatal("template string too long");
	dir = mkdtemp(ढाँचा);
	अगर (dir == शून्य) {
		लिखो_त्रुटि("mkdtemp");
		निकास(1);
	}
	माला_दो(dir);
	वापस 0;
}
