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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <errno.h>
#شامل <stdlib.h>
#شامل <stddef.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

نویسه *sftp_realpath(ثابت نویسه *path, نویسه *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
نویسه *
sftp_realpath(ثابت نویسه *path, نویسه *resolved)
{
	ساختار stat sb;
	نویسه *p, *q, *s;
	size_t چپ_len, resolved_len;
	unsigned symlinks;
	صحیح serrno, slen, mem_allocated;
	نویسه چپ[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	اگر (path[0] == '\0') {
		errno = ENOENT;
		بازگشت (پوچ);
	}

	serrno = errno;

	اگر (resolved == پوچ) {
		resolved = malloc(PATH_MAX);
		اگر (resolved == پوچ)
			بازگشت (پوچ);
		mem_allocated = 1;
	} وگرنه
		mem_allocated = 0;

	symlinks = 0;
	اگر (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		اگر (path[1] == '\0')
			بازگشت (resolved);
		resolved_len = 1;
		چپ_len = strlcpy(چپ, path + 1, اندازه(چپ));
	} وگرنه {
		اگر (getcwd(resolved, PATH_MAX) == پوچ) {
			اگر (mem_allocated)
				آزاد(resolved);
			وگرنه
				strlcpy(resolved, ".", PATH_MAX);
			بازگشت (پوچ);
		}
		resolved_len = strlen(resolved);
		چپ_len = strlcpy(چپ, path, اندازه(چپ));
	}
	اگر (چپ_len >= اندازه(چپ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		برو err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	وقتی (چپ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(چپ, '/');
		s = p ? p : چپ + چپ_len;
		اگر (s - چپ >= (ptrdiff_t)اندازه(next_token)) {
			errno = ENAMETOOLONG;
			برو err;
		}
		memcpy(next_token, چپ, s - چپ);
		next_token[s - چپ] = '\0';
		چپ_len -= s - چپ;
		اگر (p != پوچ)
			memmove(چپ, s + 1, چپ_len + 1);
		اگر (resolved[resolved_len - 1] != '/') {
			اگر (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				برو err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		اگر (next_token[0] == '\0')
			ادامه;
		وگرنه اگر (strcmp(next_token, ".") == 0)
			ادامه;
		وگرنه اگر (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			اگر (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ادامه;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		اگر (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			برو err;
		}
		اگر (lstat(resolved, &sb) != 0) {
			اگر (errno == ENOENT && p == پوچ) {
				errno = serrno;
				بازگشت (resolved);
			}
			برو err;
		}
		اگر (S_ISLNK(sb.st_mode)) {
			اگر (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				برو err;
			}
			slen = readlink(resolved, symlink, اندازه(symlink) - 1);
			اگر (slen < 0)
				برو err;
			symlink[slen] = '\0';
			اگر (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} وگرنه اگر (resolved_len > 1) {
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
			اگر (p != پوچ) {
				اگر (symlink[slen - 1] != '/') {
					اگر (slen + 1 >=
					    (ptrdiff_t)اندازه(symlink)) {
						errno = ENAMETOOLONG;
						برو err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				چپ_len = strlcat(symlink, چپ, اندازه(symlink));
				اگر (چپ_len >= اندازه(symlink)) {
					errno = ENAMETOOLONG;
					برو err;
				}
			}
			چپ_len = strlcpy(چپ, symlink, اندازه(چپ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	اگر (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	بازگشت (resolved);

err:
	اگر (mem_allocated)
		آزاد(resolved);
	بازگشت (پوچ);
}
