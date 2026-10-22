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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <stddef.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

حرف *sftp_realpath(ثابت حرف *path, حرف *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
حرف *
sftp_realpath(ثابت حرف *path, حرف *resolved)
{
	بنية stat sb;
	حرف *p, *q, *s;
	size_t left_len, resolved_len;
	unsigned symlinks;
	صحيح serrno, slen, mem_allocated;
	حرف left[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	𐡄𐡍 (path[0] == '\0') {
		errno = ENOENT;
		أرجع (عدم);
	}

	serrno = errno;

	𐡄𐡍 (resolved == عدم) {
		resolved = malloc(PATH_MAX);
		𐡄𐡍 (resolved == عدم)
			أرجع (عدم);
		mem_allocated = 1;
	} وإلا
		mem_allocated = 0;

	symlinks = 0;
	𐡄𐡍 (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		𐡄𐡍 (path[1] == '\0')
			أرجع (resolved);
		resolved_len = 1;
		left_len = strlcpy(left, path + 1, حجم(left));
	} وإلا {
		𐡄𐡍 (getcwd(resolved, PATH_MAX) == عدم) {
			𐡄𐡍 (mem_allocated)
				حرر(resolved);
			وإلا
				strlcpy(resolved, ".", PATH_MAX);
			أرجع (عدم);
		}
		resolved_len = strlen(resolved);
		left_len = strlcpy(left, path, حجم(left));
	}
	𐡄𐡍 (left_len >= حجم(left) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		اذهب err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	طالما (left_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(left, '/');
		s = p ? p : left + left_len;
		𐡄𐡍 (s - left >= (ptrdiff_t)حجم(next_token)) {
			errno = ENAMETOOLONG;
			اذهب err;
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		left_len -= s - left;
		𐡄𐡍 (p != عدم)
			memmove(left, s + 1, left_len + 1);
		𐡄𐡍 (resolved[resolved_len - 1] != '/') {
			𐡄𐡍 (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				اذهب err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		𐡄𐡍 (next_token[0] == '\0')
			استمر;
		وإلا 𐡄𐡍 (strcmp(next_token, ".") == 0)
			استمر;
		وإلا 𐡄𐡍 (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			𐡄𐡍 (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			استمر;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		𐡄𐡍 (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			اذهب err;
		}
		𐡄𐡍 (lstat(resolved, &sb) != 0) {
			𐡄𐡍 (errno == ENOENT && p == عدم) {
				errno = serrno;
				أرجع (resolved);
			}
			اذهب err;
		}
		𐡄𐡍 (S_ISLNK(sb.st_mode)) {
			𐡄𐡍 (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				اذهب err;
			}
			slen = readlink(resolved, symlink, حجم(symlink) - 1);
			𐡄𐡍 (slen < 0)
				اذهب err;
			symlink[slen] = '\0';
			𐡄𐡍 (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} وإلا 𐡄𐡍 (resolved_len > 1) {
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
			𐡄𐡍 (p != عدم) {
				𐡄𐡍 (symlink[slen - 1] != '/') {
					𐡄𐡍 (slen + 1 >=
					    (ptrdiff_t)حجم(symlink)) {
						errno = ENAMETOOLONG;
						اذهب err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				left_len = strlcat(symlink, left, حجم(symlink));
				𐡄𐡍 (left_len >= حجم(symlink)) {
					errno = ENAMETOOLONG;
					اذهب err;
				}
			}
			left_len = strlcpy(left, symlink, حجم(left));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	𐡄𐡍 (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	أرجع (resolved);

err:
	𐡄𐡍 (mem_allocated)
		حرر(resolved);
	أرجع (عدم);
}
