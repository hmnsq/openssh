/*	$OpenBSD: sftp-realpath.c,v 1.2 2021/09/02 21:03:54 deraadt Exp $ */
/*
 * Copyright (c) 2003 Constantin S. Svintsoff <kostik@iclub.nsu.ru>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

অক্ষর *sftp_realpath(ধ্রুবক অক্ষর *path, অক্ষর *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
অক্ষর *
sftp_realpath(ধ্রুবক অক্ষর *path, অক্ষর *resolved)
{
	কাঠামো stat sb;
	অক্ষর *p, *q, *s;
	আকার_t বাম_len, resolved_len;
	unsigned symlinks;
	পূর্ণসংখ্যা serrno, slen, mem_allocated;
	অক্ষর বাম[PATH_MAX], পরবর্তী_token[PATH_MAX], symlink[PATH_MAX];

	যদি (path[0] == '\0') {
		errno = ENOENT;
		ফেরত (ফাঁকা);
	}

	serrno = errno;

	যদি (resolved == ফাঁকা) {
		resolved = malloc(PATH_MAX);
		যদি (resolved == ফাঁকা)
			ফেরত (ফাঁকা);
		mem_allocated = 1;
	} অন্যথা
		mem_allocated = 0;

	symlinks = 0;
	যদি (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		যদি (path[1] == '\0')
			ফেরত (resolved);
		resolved_len = 1;
		বাম_len = strlcpy(বাম, path + 1, আকার(বাম));
	} অন্যথা {
		যদি (getcwd(resolved, PATH_MAX) == ফাঁকা) {
			যদি (mem_allocated)
				মুক্ত(resolved);
			অন্যথা
				strlcpy(resolved, ".", PATH_MAX);
			ফেরত (ফাঁকা);
		}
		resolved_len = strlen(resolved);
		বাম_len = strlcpy(বাম, path, আকার(বাম));
	}
	যদি (বাম_len >= আকার(বাম) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		যাও err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	যখন (বাম_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(বাম, '/');
		s = p ? p : বাম + বাম_len;
		যদি (s - বাম >= (ptrdiff_t)আকার(পরবর্তী_token)) {
			errno = ENAMETOOLONG;
			যাও err;
		}
		memcpy(পরবর্তী_token, বাম, s - বাম);
		পরবর্তী_token[s - বাম] = '\0';
		বাম_len -= s - বাম;
		যদি (p != ফাঁকা)
			memmove(বাম, s + 1, বাম_len + 1);
		যদি (resolved[resolved_len - 1] != '/') {
			যদি (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				যাও err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		যদি (পরবর্তী_token[0] == '\0')
			চালু;
		অন্যথা যদি (strcmp(পরবর্তী_token, ".") == 0)
			চালু;
		অন্যথা যদি (strcmp(পরবর্তী_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			যদি (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			চালু;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, পরবর্তী_token, PATH_MAX);
		যদি (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			যাও err;
		}
		যদি (lstat(resolved, &sb) != 0) {
			যদি (errno == ENOENT && p == ফাঁকা) {
				errno = serrno;
				ফেরত (resolved);
			}
			যাও err;
		}
		যদি (S_ISLNK(sb.st_mode)) {
			যদি (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				যাও err;
			}
			slen = readlink(resolved, symlink, আকার(symlink) - 1);
			যদি (slen < 0)
				যাও err;
			symlink[slen] = '\0';
			যদি (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} অন্যথা যদি (resolved_len > 1) {
				/* Strip the last path component. */
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}

			/*
			 * If there are any path components left, then
			 * append them to symlink. The result is placed
			 * in `left'.
			 */
			যদি (p != ফাঁকা) {
				যদি (symlink[slen - 1] != '/') {
					যদি (slen + 1 >=
					    (ptrdiff_t)আকার(symlink)) {
						errno = ENAMETOOLONG;
						যাও err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				বাম_len = strlcat(symlink, বাম, আকার(symlink));
				যদি (বাম_len >= আকার(symlink)) {
					errno = ENAMETOOLONG;
					যাও err;
				}
			}
			বাম_len = strlcpy(বাম, symlink, আকার(বাম));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	যদি (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ফেরত (resolved);

err:
	যদি (mem_allocated)
		মুক্ত(resolved);
	ফেরত (ফাঁকা);
}
