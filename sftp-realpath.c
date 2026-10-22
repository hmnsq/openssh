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

var_na *sftp_realpath(const var_na *path, var_na *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
var_na *
sftp_realpath(const var_na *path, var_na *resolved)
{
	sa_nracanaa stat sb;
	var_na *p, *q, *s;
	size_t left_len, resolved_len;
	unsigned symlinks;
	puur_naa_nka serrno, slen, mem_allocated;
	var_na left[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	ᰀᰧ (path[0] == '\0') {
		errno = ENOENT;
		ᰀᰧᰌ (NULL);
	}

	serrno = errno;

	ᰀᰧ (resolved == NULL) {
		resolved = malloc(PATH_MAX);
		ᰀᰧ (resolved == NULL)
			ᰀᰧᰌ (NULL);
		mem_allocated = 1;
	} ᰀᰧᰀ
		mem_allocated = 0;

	symlinks = 0;
	ᰀᰧ (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ᰀᰧ (path[1] == '\0')
			ᰀᰧᰌ (resolved);
		resolved_len = 1;
		left_len = strlcpy(left, path + 1, parimaa_na(left));
	} ᰀᰧᰀ {
		ᰀᰧ (getcwd(resolved, PATH_MAX) == NULL) {
			ᰀᰧ (mem_allocated)
				free(resolved);
			ᰀᰧᰀ
				strlcpy(resolved, ".", PATH_MAX);
			ᰀᰧᰌ (NULL);
		}
		resolved_len = strlen(resolved);
		left_len = strlcpy(left, path, parimaa_na(left));
	}
	ᰀᰧ (left_len >= parimaa_na(left) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		goto err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ᰀᰬ (left_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(left, '/');
		s = p ? p : left + left_len;
		ᰀᰧ (s - left >= (ptrdiff_t)parimaa_na(next_token)) {
			errno = ENAMETOOLONG;
			goto err;
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		left_len -= s - left;
		ᰀᰧ (p != NULL)
			memmove(left, s + 1, left_len + 1);
		ᰀᰧ (resolved[resolved_len - 1] != '/') {
			ᰀᰧ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				goto err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ᰀᰧ (next_token[0] == '\0')
			continue;
		ᰀᰧᰀ ᰀᰧ (strcmp(next_token, ".") == 0)
			continue;
		ᰀᰧᰀ ᰀᰧ (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ᰀᰧ (resolved_len > 1) {
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
		ᰀᰧ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			goto err;
		}
		ᰀᰧ (lstat(resolved, &sb) != 0) {
			ᰀᰧ (errno == ENOENT && p == NULL) {
				errno = serrno;
				ᰀᰧᰌ (resolved);
			}
			goto err;
		}
		ᰀᰧ (S_ISLNK(sb.st_mode)) {
			ᰀᰧ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				goto err;
			}
			slen = readlink(resolved, symlink, parimaa_na(symlink) - 1);
			ᰀᰧ (slen < 0)
				goto err;
			symlink[slen] = '\0';
			ᰀᰧ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ᰀᰧᰀ ᰀᰧ (resolved_len > 1) {
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
			ᰀᰧ (p != NULL) {
				ᰀᰧ (symlink[slen - 1] != '/') {
					ᰀᰧ (slen + 1 >=
					    (ptrdiff_t)parimaa_na(symlink)) {
						errno = ENAMETOOLONG;
						goto err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				left_len = strlcat(symlink, left, parimaa_na(symlink));
				ᰀᰧ (left_len >= parimaa_na(symlink)) {
					errno = ENAMETOOLONG;
					goto err;
				}
			}
			left_len = strlcpy(left, symlink, parimaa_na(left));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ᰀᰧ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ᰀᰧᰌ (resolved);

err:
	ᰀᰧ (mem_allocated)
		free(resolved);
	ᰀᰧᰌ (NULL);
}
