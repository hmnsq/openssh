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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

எழுத்து *sftp_realpath(மாறிலி எழுத்து *path, எழுத்து *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
எழுத்து *
sftp_realpath(மாறிலி எழுத்து *path, எழுத்து *resolved)
{
	கட்டமைப்பு stat sb;
	எழுத்து *p, *q, *s;
	size_t இடது_len, resolved_len;
	unsigned symlinks;
	முழு serrno, slen, mem_allocated;
	எழுத்து இடது[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	எனில் (path[0] == '\0') {
		errno = ENOENT;
		திரும்பு (வெற்று);
	}

	serrno = errno;

	எனில் (resolved == வெற்று) {
		resolved = malloc(PATH_MAX);
		எனில் (resolved == வெற்று)
			திரும்பு (வெற்று);
		mem_allocated = 1;
	} இல்லையெனில்
		mem_allocated = 0;

	symlinks = 0;
	எனில் (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		எனில் (path[1] == '\0')
			திரும்பு (resolved);
		resolved_len = 1;
		இடது_len = strlcpy(இடது, path + 1, அளவு(இடது));
	} இல்லையெனில் {
		எனில் (getcwd(resolved, PATH_MAX) == வெற்று) {
			எனில் (mem_allocated)
				விடுவி(resolved);
			இல்லையெனில்
				strlcpy(resolved, ".", PATH_MAX);
			திரும்பு (வெற்று);
		}
		resolved_len = strlen(resolved);
		இடது_len = strlcpy(இடது, path, அளவு(இடது));
	}
	எனில் (இடது_len >= அளவு(இடது) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		செல் err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	போது (இடது_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(இடது, '/');
		s = p ? p : இடது + இடது_len;
		எனில் (s - இடது >= (ptrdiff_t)அளவு(next_token)) {
			errno = ENAMETOOLONG;
			செல் err;
		}
		memcpy(next_token, இடது, s - இடது);
		next_token[s - இடது] = '\0';
		இடது_len -= s - இடது;
		எனில் (p != வெற்று)
			memmove(இடது, s + 1, இடது_len + 1);
		எனில் (resolved[resolved_len - 1] != '/') {
			எனில் (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				செல் err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		எனில் (next_token[0] == '\0')
			தொடர்;
		இல்லையெனில் எனில் (strcmp(next_token, ".") == 0)
			தொடர்;
		இல்லையெனில் எனில் (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			எனில் (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			தொடர்;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		எனில் (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			செல் err;
		}
		எனில் (lstat(resolved, &sb) != 0) {
			எனில் (errno == ENOENT && p == வெற்று) {
				errno = serrno;
				திரும்பு (resolved);
			}
			செல் err;
		}
		எனில் (S_ISLNK(sb.st_mode)) {
			எனில் (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				செல் err;
			}
			slen = readlink(resolved, symlink, அளவு(symlink) - 1);
			எனில் (slen < 0)
				செல் err;
			symlink[slen] = '\0';
			எனில் (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} இல்லையெனில் எனில் (resolved_len > 1) {
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
			எனில் (p != வெற்று) {
				எனில் (symlink[slen - 1] != '/') {
					எனில் (slen + 1 >=
					    (ptrdiff_t)அளவு(symlink)) {
						errno = ENAMETOOLONG;
						செல் err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				இடது_len = strlcat(symlink, இடது, அளவு(symlink));
				எனில் (இடது_len >= அளவு(symlink)) {
					errno = ENAMETOOLONG;
					செல் err;
				}
			}
			இடது_len = strlcpy(இடது, symlink, அளவு(இடது));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	எனில் (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	திரும்பு (resolved);

err:
	எனில் (mem_allocated)
		விடுவி(resolved);
	திரும்பு (வெற்று);
}
