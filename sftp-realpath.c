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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

char *sftp_realpath(const char *path, char *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
char *
sftp_realpath(const char *path, char *resolved)
{
	struct stat sb;
	char *p, *q, *s;
	size_t left_len, resolved_len;
	unsigned symlinks;
	цяло serrno, slen, mem_allocated;
	char left[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	ако (path[0] == '\0') {
		errno = ENOENT;
		върни (NULL);
	}

	serrno = errno;

	ако (resolved == NULL) {
		resolved = malloc(PATH_MAX);
		ако (resolved == NULL)
			върни (NULL);
		mem_allocated = 1;
	} иначе
		mem_allocated = 0;

	symlinks = 0;
	ако (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ако (path[1] == '\0')
			върни (resolved);
		resolved_len = 1;
		left_len = strlcpy(left, path + 1, sizeof(left));
	} иначе {
		ако (getcwd(resolved, PATH_MAX) == NULL) {
			ако (mem_allocated)
				free(resolved);
			иначе
				strlcpy(resolved, ".", PATH_MAX);
			върни (NULL);
		}
		resolved_len = strlen(resolved);
		left_len = strlcpy(left, path, sizeof(left));
	}
	ако (left_len >= sizeof(left) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		goto err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	докато (left_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(left, '/');
		s = p ? p : left + left_len;
		ако (s - left >= (ptrdiff_t)sizeof(next_token)) {
			errno = ENAMETOOLONG;
			goto err;
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		left_len -= s - left;
		ако (p != NULL)
			memmove(left, s + 1, left_len + 1);
		ако (resolved[resolved_len - 1] != '/') {
			ако (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				goto err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ако (next_token[0] == '\0')
			continue;
		иначе ако (strcmp(next_token, ".") == 0)
			continue;
		иначе ако (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ако (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			continue;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		ако (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			goto err;
		}
		ако (lstat(resolved, &sb) != 0) {
			ако (errno == ENOENT && p == NULL) {
				errno = serrno;
				върни (resolved);
			}
			goto err;
		}
		ако (S_ISLNK(sb.st_mode)) {
			ако (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				goto err;
			}
			slen = readlink(resolved, symlink, sizeof(symlink) - 1);
			ако (slen < 0)
				goto err;
			symlink[slen] = '\0';
			ако (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} иначе ако (resolved_len > 1) {
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
			ако (p != NULL) {
				ако (symlink[slen - 1] != '/') {
					ако (slen + 1 >=
					    (ptrdiff_t)sizeof(symlink)) {
						errno = ENAMETOOLONG;
						goto err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				left_len = strlcat(symlink, left, sizeof(symlink));
				ако (left_len >= sizeof(symlink)) {
					errno = ENAMETOOLONG;
					goto err;
				}
			}
			left_len = strlcpy(left, symlink, sizeof(left));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ако (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	върни (resolved);

err:
	ако (mem_allocated)
		free(resolved);
	върни (NULL);
}
