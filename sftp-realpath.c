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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SYMLOOP_MAX
# define SYMLOOP_MAX 32
#ਜੇ_ਅੰਤ

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

ਅੱਖਰ *sftp_realpath(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅੱਖਰ *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
ਅੱਖਰ *
sftp_realpath(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅੱਖਰ *resolved)
{
	ਬਣਤਰ stat sb;
	ਅੱਖਰ *p, *q, *s;
	ਮਾਪ_t ਖੱਬਾ_len, resolved_len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ symlinks;
	ਪੂਰਨ serrno, slen, mem_allocated;
	ਅੱਖਰ ਖੱਬਾ[PATH_MAX], ਅਗਲਾ_token[PATH_MAX], symlink[PATH_MAX];

	ਜੇ (ਰਸਤਾ[0] == '\0') {
		errno = ENOENT;
		ਵਾਪਸ (ਨਿਰਾ);
	}

	serrno = errno;

	ਜੇ (resolved == ਨਿਰਾ) {
		resolved = ਸਮ੍ਰਿਤੀ_ਦਿਓ(PATH_MAX);
		ਜੇ (resolved == ਨਿਰਾ)
			ਵਾਪਸ (ਨਿਰਾ);
		mem_allocated = 1;
	} ਨਹੀਂਤਾਂ
		mem_allocated = 0;

	symlinks = 0;
	ਜੇ (ਰਸਤਾ[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ਜੇ (ਰਸਤਾ[1] == '\0')
			ਵਾਪਸ (resolved);
		resolved_len = 1;
		ਖੱਬਾ_len = strlcpy(ਖੱਬਾ, ਰਸਤਾ + 1, ਆਕਾਰ(ਖੱਬਾ));
	} ਨਹੀਂਤਾਂ {
		ਜੇ (getcwd(resolved, PATH_MAX) == ਨਿਰਾ) {
			ਜੇ (mem_allocated)
				ਮੁਕਤ(resolved);
			ਨਹੀਂਤਾਂ
				strlcpy(resolved, ".", PATH_MAX);
			ਵਾਪਸ (ਨਿਰਾ);
		}
		resolved_len = ਲੜੀ_ਲੰਬਾਈ(resolved);
		ਖੱਬਾ_len = strlcpy(ਖੱਬਾ, ਰਸਤਾ, ਆਕਾਰ(ਖੱਬਾ));
	}
	ਜੇ (ਖੱਬਾ_len >= ਆਕਾਰ(ਖੱਬਾ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		ਜਾਓ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ਜਦੋਂ (ਖੱਬਾ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ਖੱਬਾ, '/');
		s = p ? p : ਖੱਬਾ + ਖੱਬਾ_len;
		ਜੇ (s - ਖੱਬਾ >= (ptrdiff_t)ਆਕਾਰ(ਅਗਲਾ_token)) {
			errno = ENAMETOOLONG;
			ਜਾਓ err;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਅਗਲਾ_token, ਖੱਬਾ, s - ਖੱਬਾ);
		ਅਗਲਾ_token[s - ਖੱਬਾ] = '\0';
		ਖੱਬਾ_len -= s - ਖੱਬਾ;
		ਜੇ (p != ਨਿਰਾ)
			memmove(ਖੱਬਾ, s + 1, ਖੱਬਾ_len + 1);
		ਜੇ (resolved[resolved_len - 1] != '/') {
			ਜੇ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				ਜਾਓ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ਜੇ (ਅਗਲਾ_token[0] == '\0')
			ਜਾਰੀ;
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਅਗਲਾ_token, ".") == 0)
			ਜਾਰੀ;
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(ਅਗਲਾ_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ਜੇ (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ਜਾਰੀ;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, ਅਗਲਾ_token, PATH_MAX);
		ਜੇ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			ਜਾਓ err;
		}
		ਜੇ (lstat(resolved, &sb) != 0) {
			ਜੇ (errno == ENOENT && p == ਨਿਰਾ) {
				errno = serrno;
				ਵਾਪਸ (resolved);
			}
			ਜਾਓ err;
		}
		ਜੇ (S_ISLNK(sb.st_mode)) {
			ਜੇ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				ਜਾਓ err;
			}
			slen = readlink(resolved, symlink, ਆਕਾਰ(symlink) - 1);
			ਜੇ (slen < 0)
				ਜਾਓ err;
			symlink[slen] = '\0';
			ਜੇ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (resolved_len > 1) {
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
			ਜੇ (p != ਨਿਰਾ) {
				ਜੇ (symlink[slen - 1] != '/') {
					ਜੇ (slen + 1 >=
					    (ptrdiff_t)ਆਕਾਰ(symlink)) {
						errno = ENAMETOOLONG;
						ਜਾਓ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ਖੱਬਾ_len = strlcat(symlink, ਖੱਬਾ, ਆਕਾਰ(symlink));
				ਜੇ (ਖੱਬਾ_len >= ਆਕਾਰ(symlink)) {
					errno = ENAMETOOLONG;
					ਜਾਓ err;
				}
			}
			ਖੱਬਾ_len = strlcpy(ਖੱਬਾ, symlink, ਆਕਾਰ(ਖੱਬਾ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ਜੇ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ਵਾਪਸ (resolved);

err:
	ਜੇ (mem_allocated)
		ਮੁਕਤ(resolved);
	ਵਾਪਸ (ਨਿਰਾ);
}
