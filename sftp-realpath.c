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

#اگر_غیر_تعریف_شدہ SYMLOOP_MAX
# define SYMLOOP_MAX 32
#اگر_ختم

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

حرف *sftp_realpath(ثابت حرف *راستہ, حرف *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
حرف *
sftp_realpath(ثابت حرف *راستہ, حرف *resolved)
{
	ساخت stat sb;
	حرف *p, *q, *s;
	سائز_t بایاں_len, resolved_len;
	غیرعلامتی symlinks;
	صحیح serrno, slen, mem_allocated;
	حرف بایاں[PATH_MAX], اگلا_token[PATH_MAX], symlink[PATH_MAX];

	اگر (راستہ[0] == '\0') {
		errno = ENOENT;
		واپس (تہی);
	}

	serrno = errno;

	اگر (resolved == تہی) {
		resolved = حافظہ_دو(PATH_MAX);
		اگر (resolved == تہی)
			واپس (تہی);
		mem_allocated = 1;
	} ورنہ
		mem_allocated = 0;

	symlinks = 0;
	اگر (راستہ[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		اگر (راستہ[1] == '\0')
			واپس (resolved);
		resolved_len = 1;
		بایاں_len = strlcpy(بایاں, راستہ + 1, حجم(بایاں));
	} ورنہ {
		اگر (getcwd(resolved, PATH_MAX) == تہی) {
			اگر (mem_allocated)
				آزاد(resolved);
			ورنہ
				strlcpy(resolved, ".", PATH_MAX);
			واپس (تہی);
		}
		resolved_len = لڑی_لمبائی(resolved);
		بایاں_len = strlcpy(بایاں, راستہ, حجم(بایاں));
	}
	اگر (بایاں_len >= حجم(بایاں) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		جاؤ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	جب (بایاں_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(بایاں, '/');
		s = p ? p : بایاں + بایاں_len;
		اگر (s - بایاں >= (ptrdiff_t)حجم(اگلا_token)) {
			errno = ENAMETOOLONG;
			جاؤ err;
		}
		حافظہ_نقل(اگلا_token, بایاں, s - بایاں);
		اگلا_token[s - بایاں] = '\0';
		بایاں_len -= s - بایاں;
		اگر (p != تہی)
			memmove(بایاں, s + 1, بایاں_len + 1);
		اگر (resolved[resolved_len - 1] != '/') {
			اگر (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				جاؤ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		اگر (اگلا_token[0] == '\0')
			جاری;
		ورنہ اگر (strcmp(اگلا_token, ".") == 0)
			جاری;
		ورنہ اگر (strcmp(اگلا_token, "..") == 0) {
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
			جاری;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, اگلا_token, PATH_MAX);
		اگر (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			جاؤ err;
		}
		اگر (lstat(resolved, &sb) != 0) {
			اگر (errno == ENOENT && p == تہی) {
				errno = serrno;
				واپس (resolved);
			}
			جاؤ err;
		}
		اگر (S_ISLNK(sb.st_mode)) {
			اگر (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				جاؤ err;
			}
			slen = readlink(resolved, symlink, حجم(symlink) - 1);
			اگر (slen < 0)
				جاؤ err;
			symlink[slen] = '\0';
			اگر (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ورنہ اگر (resolved_len > 1) {
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
			اگر (p != تہی) {
				اگر (symlink[slen - 1] != '/') {
					اگر (slen + 1 >=
					    (ptrdiff_t)حجم(symlink)) {
						errno = ENAMETOOLONG;
						جاؤ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				بایاں_len = strlcat(symlink, بایاں, حجم(symlink));
				اگر (بایاں_len >= حجم(symlink)) {
					errno = ENAMETOOLONG;
					جاؤ err;
				}
			}
			بایاں_len = strlcpy(بایاں, symlink, حجم(بایاں));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	اگر (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	واپس (resolved);

err:
	اگر (mem_allocated)
		آزاد(resolved);
	واپس (تہی);
}
