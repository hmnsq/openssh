/* THIS FILE HAS BEEN MODIFIED FROM THE ORIGINAL OPENBSD SOURCE */
/* Changes: Removed mktemp */

/*	$OpenBSD: mktemp.c,v 1.30 2010/03/21 23:09:30 schwarze Exp $ */
/*
 * Copyright (c) 1996-1998, 2008 Theo de Raadt
 * Copyright (c) 1997, 2008-2009 Todd C. Miller
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

/* OPENBSD ORIGINAL: lib/libc/stdio/mktemp.c */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <ctype.h>
#समावेश <unistd.h>

#अगर_घोषित mkstemp
#अघोषित mkstemp
#पूर्ण_अगर
पूर्णांक mkstemp(अक्षर *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
पूर्णांक
_ssh_mkstemp(अक्षर *ढाँचा)
{
	mode_t mask;
	पूर्णांक ret;

	mask = umask(0177);
	ret = mkstemp(ढाँचा);
	(व्योम)umask(mask);
	वापस ret;
}

#अगर !defined(HAVE_MKDTEMP)

#घोषणा MKTEMP_NAME	0
#घोषणा MKTEMP_FILE	1
#घोषणा MKTEMP_DIR	2

#घोषणा TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#घोषणा अंक_CHARS	(माप(TEMPCHARS) - 1)

अटल पूर्णांक
mktemp_internal(अक्षर *path, पूर्णांक slen, पूर्णांक mode)
{
	अक्षर *start, *cp, *ep;
	स्थिर अक्षर *tempchars = TEMPCHARS;
	अचिन्हित पूर्णांक r, tries;
	काष्ठा stat sb;
	माप_प्रकार len;
	पूर्णांक fd;

	len = म_माप(path);
	अगर (len == 0 || slen < 0 || (माप_प्रकार)slen >= len) {
		त्रुटि_सं = EINVAL;
		वापस(-1);
	}
	ep = path + len - slen;

	tries = 1;
	क्रम (start = ep; start > path && start[-1] == 'X'; start--) {
		अगर (tries < पूर्णांक_उच्च / अंक_CHARS)
			tries *= अंक_CHARS;
	}
	tries *= 2;

	करो {
		क्रम (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(अंक_CHARS);
			*cp = tempchars[r];
		}

		चयन (mode) {
		हाल MKTEMP_NAME:
			अगर (lstat(path, &sb) != 0)
				वापस(त्रुटि_सं == ENOENT ? 0 : -1);
			अवरोध;
		हाल MKTEMP_FILE:
			fd = खोलो(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			अगर (fd != -1 || त्रुटि_सं != EEXIST)
				वापस(fd);
			अवरोध;
		हाल MKTEMP_DIR:
			अगर (सूची_गढ़ो(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				वापस(0);
			अगर (त्रुटि_सं != EEXIST)
				वापस(-1);
			अवरोध;
		}
	} जबतक (--tries);

	त्रुटि_सं = EEXIST;
	वापस(-1);
}

#अगर 0
अक्षर *_mktemp(अक्षर *);

अक्षर *
_mktemp(अक्षर *path)
{
	अगर (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		वापस(शून्य);
	वापस(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

अक्षर *
mktemp(अक्षर *path)
{
	वापस(_mktemp(path));
}
#पूर्ण_अगर

पूर्णांक
mkstemp(अक्षर *path)
{
	वापस(mktemp_internal(path, 0, MKTEMP_FILE));
}

पूर्णांक
mkstemps(अक्षर *path, पूर्णांक slen)
{
	वापस(mktemp_internal(path, slen, MKTEMP_FILE));
}

अक्षर *
mkdtemp(अक्षर *path)
{
	पूर्णांक error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	वापस(error ? शून्य : path);
}

#पूर्ण_अगर /* !defined(HAVE_MKDTEMP) */
