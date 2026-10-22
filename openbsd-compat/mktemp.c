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

#यदि_परिभाषितम् mkstemp
#अपरिभाषय mkstemp
#यदि_अन्तः
पूर्णाङ्क mkstemp(वर्ण *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
पूर्णाङ्क
_ssh_mkstemp(वर्ण *प्रतिरूपम्)
{
	बहुलकम्_t आवरणम्;
	पूर्णाङ्क ret;

	आवरणम् = umask(0177);
	ret = mkstemp(प्रतिरूपम्);
	(शून्य)umask(आवरणम्);
	प्रत्यागम ret;
}

#यदि !defined(HAVE_MKDTEMP)

#परिभाषय MKTEMP_NAME	0
#परिभाषय MKTEMP_FILE	1
#परिभाषय MKTEMP_DIR	2

#परिभाषय TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#परिभाषय अङ्कः_CHARS	(परिमाण(TEMPCHARS) - 1)

स्थिर पूर्णाङ्क
mktemp_आन्तरिकम्(वर्ण *मार्गः, पूर्णाङ्क slen, पूर्णाङ्क बहुलकम्)
{
	वर्ण *start, *cp, *ep;
	ध्रुव वर्ण *tempchars = TEMPCHARS;
	अचिह्नित पूर्णाङ्क r, tries;
	संरचना stat sb;
	आकार_t len;
	पूर्णाङ्क fd;

	len = वाक्यदैर्घ्यम्(मार्गः);
	यदि (len == 0 || slen < 0 || (आकार_t)slen >= len) {
		errno = EINVAL;
		प्रत्यागम(-1);
	}
	ep = मार्गः + len - slen;

	tries = 1;
	प्रति (start = ep; start > मार्गः && start[-1] == 'X'; start--) {
		यदि (tries < अधिकतम_पूर्णाङ्कः / अङ्कः_CHARS)
			tries *= अङ्कः_CHARS;
	}
	tries *= 2;

	कुरु {
		प्रति (cp = start; cp != ep; cp++) {
			r = arc4random_एकरूपम्(अङ्कः_CHARS);
			*cp = tempchars[r];
		}

		विकल्प (बहुलकम्) {
		पक्ष MKTEMP_NAME:
			यदि (lstat(मार्गः, &sb) != 0)
				प्रत्यागम(errno == ENOENT ? 0 : -1);
			भङ्ग;
		पक्ष MKTEMP_FILE:
			fd = उद्घाटय(मार्गः, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			यदि (fd != -1 || errno != EEXIST)
				प्रत्यागम(fd);
			भङ्ग;
		पक्ष MKTEMP_DIR:
			यदि (mkdir(मार्गः, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				प्रत्यागम(0);
			यदि (errno != EEXIST)
				प्रत्यागम(-1);
			भङ्ग;
		}
	} यावत् (--tries);

	errno = EEXIST;
	प्रत्यागम(-1);
}

#यदि 0
वर्ण *_mktemp(वर्ण *);

वर्ण *
_mktemp(वर्ण *मार्गः)
{
	यदि (mktemp_आन्तरिकम्(मार्गः, 0, MKTEMP_NAME) == -1)
		प्रत्यागम(रिक्त);
	प्रत्यागम(मार्गः);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

वर्ण *
mktemp(वर्ण *मार्गः)
{
	प्रत्यागम(_mktemp(मार्गः));
}
#यदि_अन्तः

पूर्णाङ्क
mkstemp(वर्ण *मार्गः)
{
	प्रत्यागम(mktemp_आन्तरिकम्(मार्गः, 0, MKTEMP_FILE));
}

पूर्णाङ्क
mkstemps(वर्ण *मार्गः, पूर्णाङ्क slen)
{
	प्रत्यागम(mktemp_आन्तरिकम्(मार्गः, slen, MKTEMP_FILE));
}

वर्ण *
mkdtemp(वर्ण *मार्गः)
{
	पूर्णाङ्क error;

	error = mktemp_आन्तरिकम्(मार्गः, 0, MKTEMP_DIR);
	प्रत्यागम(error ? रिक्त : मार्गः);
}

#यदि_अन्तः /* !defined(HAVE_MKDTEMP) */
