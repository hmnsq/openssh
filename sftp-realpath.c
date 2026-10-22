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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

ವರ್ಣ *sftp_realpath(ಧ್ರುವ ವರ್ಣ *path, ವರ್ಣ *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
ವರ್ಣ *
sftp_realpath(ಧ್ರುವ ವರ್ಣ *path, ವರ್ಣ *resolved)
{
	ಸಂರಚನಾ stat sb;
	ವರ್ಣ *p, *q, *s;
	size_t ಎಡ_len, resolved_len;
	unsigned symlinks;
	ಪೂರ್ಣಾಙ್ಕ serrno, slen, mem_allocated;
	ವರ್ಣ ಎಡ[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	ಯದಿ (path[0] == '\0') {
		errno = ENOENT;
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	serrno = errno;

	ಯದಿ (resolved == ರಿಕ್ತ) {
		resolved = malloc(PATH_MAX);
		ಯದಿ (resolved == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		mem_allocated = 1;
	} ಅನ್ಯಥಾ
		mem_allocated = 0;

	symlinks = 0;
	ಯದಿ (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ಯದಿ (path[1] == '\0')
			ಪ್ರತ್ಯಾಗಮ (resolved);
		resolved_len = 1;
		ಎಡ_len = strlcpy(ಎಡ, path + 1, ಪರಿಮಾಣ(ಎಡ));
	} ಅನ್ಯಥಾ {
		ಯದಿ (getcwd(resolved, PATH_MAX) == ರಿಕ್ತ) {
			ಯದಿ (mem_allocated)
				ಮುಕ್ತ(resolved);
			ಅನ್ಯಥಾ
				strlcpy(resolved, ".", PATH_MAX);
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}
		resolved_len = strlen(resolved);
		ಎಡ_len = strlcpy(ಎಡ, path, ಪರಿಮಾಣ(ಎಡ));
	}
	ಯದಿ (ಎಡ_len >= ಪರಿಮಾಣ(ಎಡ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		ಗಚ್ಛ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ಯಾವತ್ (ಎಡ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ಎಡ, '/');
		s = p ? p : ಎಡ + ಎಡ_len;
		ಯದಿ (s - ಎಡ >= (ptrdiff_t)ಪರಿಮಾಣ(next_token)) {
			errno = ENAMETOOLONG;
			ಗಚ್ಛ err;
		}
		memcpy(next_token, ಎಡ, s - ಎಡ);
		next_token[s - ಎಡ] = '\0';
		ಎಡ_len -= s - ಎಡ;
		ಯದಿ (p != ರಿಕ್ತ)
			memmove(ಎಡ, s + 1, ಎಡ_len + 1);
		ಯದಿ (resolved[resolved_len - 1] != '/') {
			ಯದಿ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				ಗಚ್ಛ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ಯದಿ (next_token[0] == '\0')
			ಅನುವರ್ತ;
		ಅನ್ಯಥಾ ಯದಿ (strcmp(next_token, ".") == 0)
			ಅನುವರ್ತ;
		ಅನ್ಯಥಾ ಯದಿ (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ಯದಿ (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ಅನುವರ್ತ;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		ಯದಿ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			ಗಚ್ಛ err;
		}
		ಯದಿ (lstat(resolved, &sb) != 0) {
			ಯದಿ (errno == ENOENT && p == ರಿಕ್ತ) {
				errno = serrno;
				ಪ್ರತ್ಯಾಗಮ (resolved);
			}
			ಗಚ್ಛ err;
		}
		ಯದಿ (S_ISLNK(sb.st_mode)) {
			ಯದಿ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				ಗಚ್ಛ err;
			}
			slen = readlink(resolved, symlink, ಪರಿಮಾಣ(symlink) - 1);
			ಯದಿ (slen < 0)
				ಗಚ್ಛ err;
			symlink[slen] = '\0';
			ಯದಿ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ಅನ್ಯಥಾ ಯದಿ (resolved_len > 1) {
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
			ಯದಿ (p != ರಿಕ್ತ) {
				ಯದಿ (symlink[slen - 1] != '/') {
					ಯದಿ (slen + 1 >=
					    (ptrdiff_t)ಪರಿಮಾಣ(symlink)) {
						errno = ENAMETOOLONG;
						ಗಚ್ಛ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ಎಡ_len = strlcat(symlink, ಎಡ, ಪರಿಮಾಣ(symlink));
				ಯದಿ (ಎಡ_len >= ಪರಿಮಾಣ(symlink)) {
					errno = ENAMETOOLONG;
					ಗಚ್ಛ err;
				}
			}
			ಎಡ_len = strlcpy(ಎಡ, symlink, ಪರಿಮಾಣ(ಎಡ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ಯದಿ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ಪ್ರತ್ಯಾಗಮ (resolved);

err:
	ಯದಿ (mem_allocated)
		ಮುಕ್ತ(resolved);
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}
