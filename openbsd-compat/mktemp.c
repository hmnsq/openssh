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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
पूर्णाङ्क mkstemp(वर्ण *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
पूर्णाङ्क
_ssh_mkstemp(वर्ण *template)
{
	mode_t mask;
	पूर्णाङ्क ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(शून्य)umask(mask);
	पटिनिवत्त ret;
}

#सचे !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define अङ्कः_CHARS	(परिमाण(TEMPCHARS) - 1)

स्थिर पूर्णाङ्क
mktemp_internal(वर्ण *path, पूर्णाङ्क slen, पूर्णाङ्क mode)
{
	वर्ण *start, *cp, *ep;
	ध्रुव वर्ण *tempchars = TEMPCHARS;
	unsigned पूर्णाङ्क r, tries;
	संरचना stat sb;
	size_t len;
	पूर्णाङ्क fd;

	len = strlen(path);
	सचे (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		पटिनिवत्त(-1);
	}
	ep = path + len - slen;

	tries = 1;
	अत्थाय (start = ep; start > path && start[-1] == 'X'; start--) {
		सचे (tries < INT_MAX / अङ्कः_CHARS)
			tries *= अङ्कः_CHARS;
	}
	tries *= 2;

	करोहि {
		अत्थाय (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(अङ्कः_CHARS);
			*cp = tempchars[r];
		}

		विकल्प (mode) {
		पक्ष MKTEMP_NAME:
			सचे (lstat(path, &sb) != 0)
				पटिनिवत्त(errno == ENOENT ? 0 : -1);
			भङ्ग;
		पक्ष MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			सचे (fd != -1 || errno != EEXIST)
				पटिनिवत्त(fd);
			भङ्ग;
		पक्ष MKTEMP_DIR:
			सचे (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				पटिनिवत्त(0);
			सचे (errno != EEXIST)
				पटिनिवत्त(-1);
			भङ्ग;
		}
	} याव (--tries);

	errno = EEXIST;
	पटिनिवत्त(-1);
}

#सचे 0
वर्ण *_mktemp(वर्ण *);

वर्ण *
_mktemp(वर्ण *path)
{
	सचे (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		पटिनिवत्त(रिक्त);
	पटिनिवत्त(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

वर्ण *
mktemp(वर्ण *path)
{
	पटिनिवत्त(_mktemp(path));
}
#endif

पूर्णाङ्क
mkstemp(वर्ण *path)
{
	पटिनिवत्त(mktemp_internal(path, 0, MKTEMP_FILE));
}

पूर्णाङ्क
mkstemps(वर्ण *path, पूर्णाङ्क slen)
{
	पटिनिवत्त(mktemp_internal(path, slen, MKTEMP_FILE));
}

वर्ण *
mkdtemp(वर्ण *path)
{
	पूर्णाङ्क error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	पटिनिवत्त(error ? रिक्त : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
