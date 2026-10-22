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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SYMLOOP_MAX
# define SYMLOOP_MAX 32
#ಆದರೆ_ಅಂತ್ಯ

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

ಅಕ್ಷರ *sftp_realpath(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಅಕ್ಷರ *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
ಅಕ್ಷರ *
sftp_realpath(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಅಕ್ಷರ *resolved)
{
	ರಚನೆ stat sb;
	ಅಕ್ಷರ *p, *q, *s;
	ಗಾತ್ರ_t ಎಡ_len, resolved_len;
	ಚಿಹ್ನೆರಹಿತ symlinks;
	ಪೂರ್ಣಾಂಕ serrno, slen, mem_allocated;
	ಅಕ್ಷರ ಎಡ[PATH_MAX], ಮುಂದಿನ_token[PATH_MAX], symlink[PATH_MAX];

	ಆದರೆ (ಮಾರ್ಗ[0] == '\0') {
		errno = ENOENT;
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	serrno = errno;

	ಆದರೆ (resolved == ಖಾಲಿ) {
		resolved = ಸ್ಮರಣೆ_ಕೊಡು(PATH_MAX);
		ಆದರೆ (resolved == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		mem_allocated = 1;
	} ಇಲ್ಲದಿದ್ದರೆ
		mem_allocated = 0;

	symlinks = 0;
	ಆದರೆ (ಮಾರ್ಗ[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ಆದರೆ (ಮಾರ್ಗ[1] == '\0')
			ಹಿಂತಿರುಗಿ (resolved);
		resolved_len = 1;
		ಎಡ_len = strlcpy(ಎಡ, ಮಾರ್ಗ + 1, ಗಾತ್ರ(ಎಡ));
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (getcwd(resolved, PATH_MAX) == ಖಾಲಿ) {
			ಆದರೆ (mem_allocated)
				ಬಿಡುಗಡೆ(resolved);
			ಇಲ್ಲದಿದ್ದರೆ
				strlcpy(resolved, ".", PATH_MAX);
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		resolved_len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(resolved);
		ಎಡ_len = strlcpy(ಎಡ, ಮಾರ್ಗ, ಗಾತ್ರ(ಎಡ));
	}
	ಆದರೆ (ಎಡ_len >= ಗಾತ್ರ(ಎಡ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		ಹೋಗು err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ಆಗ (ಎಡ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ಎಡ, '/');
		s = p ? p : ಎಡ + ಎಡ_len;
		ಆದರೆ (s - ಎಡ >= (ptrdiff_t)ಗಾತ್ರ(ಮುಂದಿನ_token)) {
			errno = ENAMETOOLONG;
			ಹೋಗು err;
		}
		ಸ್ಮರಣೆ_ನಕಲು(ಮುಂದಿನ_token, ಎಡ, s - ಎಡ);
		ಮುಂದಿನ_token[s - ಎಡ] = '\0';
		ಎಡ_len -= s - ಎಡ;
		ಆದರೆ (p != ಖಾಲಿ)
			memmove(ಎಡ, s + 1, ಎಡ_len + 1);
		ಆದರೆ (resolved[resolved_len - 1] != '/') {
			ಆದರೆ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				ಹೋಗು err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ಆದರೆ (ಮುಂದಿನ_token[0] == '\0')
			ಮುಂದುವರಿ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ಮುಂದಿನ_token, ".") == 0)
			ಮುಂದುವರಿ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ಮುಂದಿನ_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ಆದರೆ (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ಮುಂದುವರಿ;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, ಮುಂದಿನ_token, PATH_MAX);
		ಆದರೆ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			ಹೋಗು err;
		}
		ಆದರೆ (lstat(resolved, &sb) != 0) {
			ಆದರೆ (errno == ENOENT && p == ಖಾಲಿ) {
				errno = serrno;
				ಹಿಂತಿರುಗಿ (resolved);
			}
			ಹೋಗು err;
		}
		ಆದರೆ (S_ISLNK(sb.st_mode)) {
			ಆದರೆ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				ಹೋಗು err;
			}
			slen = readlink(resolved, symlink, ಗಾತ್ರ(symlink) - 1);
			ಆದರೆ (slen < 0)
				ಹೋಗು err;
			symlink[slen] = '\0';
			ಆದರೆ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (resolved_len > 1) {
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
			ಆದರೆ (p != ಖಾಲಿ) {
				ಆದರೆ (symlink[slen - 1] != '/') {
					ಆದರೆ (slen + 1 >=
					    (ptrdiff_t)ಗಾತ್ರ(symlink)) {
						errno = ENAMETOOLONG;
						ಹೋಗು err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ಎಡ_len = strlcat(symlink, ಎಡ, ಗಾತ್ರ(symlink));
				ಆದರೆ (ಎಡ_len >= ಗಾತ್ರ(symlink)) {
					errno = ENAMETOOLONG;
					ಹೋಗು err;
				}
			}
			ಎಡ_len = strlcpy(ಎಡ, symlink, ಗಾತ್ರ(ಎಡ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ಆದರೆ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ಹಿಂತಿರುಗಿ (resolved);

err:
	ಆದರೆ (mem_allocated)
		ಬಿಡುಗಡೆ(resolved);
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}
