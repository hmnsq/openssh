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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

અક્ષર *sftp_realpath(અચલ અક્ષર *path, અક્ષર *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
અક્ષર *
sftp_realpath(અચલ અક્ષર *path, અક્ષર *resolved)
{
	સંરચના stat sb;
	અક્ષર *p, *q, *s;
	size_t ડાબું_len, resolved_len;
	unsigned symlinks;
	પૂર્ણાંક serrno, slen, mem_allocated;
	અક્ષર ડાબું[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	જો (path[0] == '\0') {
		errno = ENOENT;
		પાછા (ખાલી);
	}

	serrno = errno;

	જો (resolved == ખાલી) {
		resolved = malloc(PATH_MAX);
		જો (resolved == ખાલી)
			પાછા (ખાલી);
		mem_allocated = 1;
	} નહીંતર
		mem_allocated = 0;

	symlinks = 0;
	જો (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		જો (path[1] == '\0')
			પાછા (resolved);
		resolved_len = 1;
		ડાબું_len = strlcpy(ડાબું, path + 1, કદ(ડાબું));
	} નહીંતર {
		જો (getcwd(resolved, PATH_MAX) == ખાલી) {
			જો (mem_allocated)
				મુક્ત(resolved);
			નહીંતર
				strlcpy(resolved, ".", PATH_MAX);
			પાછા (ખાલી);
		}
		resolved_len = strlen(resolved);
		ડાબું_len = strlcpy(ડાબું, path, કદ(ડાબું));
	}
	જો (ડાબું_len >= કદ(ડાબું) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		જાઓ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	જ્યારે (ડાબું_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ડાબું, '/');
		s = p ? p : ડાબું + ડાબું_len;
		જો (s - ડાબું >= (ptrdiff_t)કદ(next_token)) {
			errno = ENAMETOOLONG;
			જાઓ err;
		}
		memcpy(next_token, ડાબું, s - ડાબું);
		next_token[s - ડાબું] = '\0';
		ડાબું_len -= s - ડાબું;
		જો (p != ખાલી)
			memmove(ડાબું, s + 1, ડાબું_len + 1);
		જો (resolved[resolved_len - 1] != '/') {
			જો (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				જાઓ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		જો (next_token[0] == '\0')
			ચાલુ;
		નહીંતર જો (strcmp(next_token, ".") == 0)
			ચાલુ;
		નહીંતર જો (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			જો (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ચાલુ;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		જો (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			જાઓ err;
		}
		જો (lstat(resolved, &sb) != 0) {
			જો (errno == ENOENT && p == ખાલી) {
				errno = serrno;
				પાછા (resolved);
			}
			જાઓ err;
		}
		જો (S_ISLNK(sb.st_mode)) {
			જો (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				જાઓ err;
			}
			slen = readlink(resolved, symlink, કદ(symlink) - 1);
			જો (slen < 0)
				જાઓ err;
			symlink[slen] = '\0';
			જો (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} નહીંતર જો (resolved_len > 1) {
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
			જો (p != ખાલી) {
				જો (symlink[slen - 1] != '/') {
					જો (slen + 1 >=
					    (ptrdiff_t)કદ(symlink)) {
						errno = ENAMETOOLONG;
						જાઓ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ડાબું_len = strlcat(symlink, ડાબું, કદ(symlink));
				જો (ડાબું_len >= કદ(symlink)) {
					errno = ENAMETOOLONG;
					જાઓ err;
				}
			}
			ડાબું_len = strlcpy(ડાબું, symlink, કદ(ડાબું));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	જો (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	પાછા (resolved);

err:
	જો (mem_allocated)
		મુક્ત(resolved);
	પાછા (ખાલી);
}
