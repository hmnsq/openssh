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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
പൂർണ്ണസംഖ്യ mkstemp(അക്ഷരം *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
പൂർണ്ണസംഖ്യ
_ssh_mkstemp(അക്ഷരം *template)
{
	mode_t mask;
	പൂർണ്ണസംഖ്യ ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(ശൂന്യം)umask(mask);
	തിരികെ ret;
}

#എങ്കിൽ !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define അക്കം_CHARS	(വലുപ്പം(TEMPCHARS) - 1)

സ്ഥിതം പൂർണ്ണസംഖ്യ
mktemp_internal(അക്ഷരം *path, പൂർണ്ണസംഖ്യ slen, പൂർണ്ണസംഖ്യ mode)
{
	അക്ഷരം *start, *cp, *ep;
	സ്ഥിരം അക്ഷരം *tempchars = TEMPCHARS;
	unsigned പൂർണ്ണസംഖ്യ r, tries;
	ഘടന stat sb;
	size_t len;
	പൂർണ്ണസംഖ്യ fd;

	len = strlen(path);
	എങ്കിൽ (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		തിരികെ(-1);
	}
	ep = path + len - slen;

	tries = 1;
	വേണ്ടി (start = ep; start > path && start[-1] == 'X'; start--) {
		എങ്കിൽ (tries < INT_MAX / അക്കം_CHARS)
			tries *= അക്കം_CHARS;
	}
	tries *= 2;

	ചെയ്യുക {
		വേണ്ടി (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(അക്കം_CHARS);
			*cp = tempchars[r];
		}

		തിരഞ്ഞെടുപ്പ് (mode) {
		അവസ്ഥ MKTEMP_NAME:
			എങ്കിൽ (lstat(path, &sb) != 0)
				തിരികെ(errno == ENOENT ? 0 : -1);
			നിർത്തുക;
		അവസ്ഥ MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			എങ്കിൽ (fd != -1 || errno != EEXIST)
				തിരികെ(fd);
			നിർത്തുക;
		അവസ്ഥ MKTEMP_DIR:
			എങ്കിൽ (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				തിരികെ(0);
			എങ്കിൽ (errno != EEXIST)
				തിരികെ(-1);
			നിർത്തുക;
		}
	} ആകുമ്പോൾ (--tries);

	errno = EEXIST;
	തിരികെ(-1);
}

#എങ്കിൽ 0
അക്ഷരം *_mktemp(അക്ഷരം *);

അക്ഷരം *
_mktemp(അക്ഷരം *path)
{
	എങ്കിൽ (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		തിരികെ(ശൂന്യ);
	തിരികെ(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

അക്ഷരം *
mktemp(അക്ഷരം *path)
{
	തിരികെ(_mktemp(path));
}
#endif

പൂർണ്ണസംഖ്യ
mkstemp(അക്ഷരം *path)
{
	തിരികെ(mktemp_internal(path, 0, MKTEMP_FILE));
}

പൂർണ്ണസംഖ്യ
mkstemps(അക്ഷരം *path, പൂർണ്ണസംഖ്യ slen)
{
	തിരികെ(mktemp_internal(path, slen, MKTEMP_FILE));
}

അക്ഷരം *
mkdtemp(അക്ഷരം *path)
{
	പൂർണ്ണസംഖ്യ error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	തിരികെ(error ? ശൂന്യ : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
