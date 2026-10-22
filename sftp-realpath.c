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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

അക്ഷരം *sftp_realpath(സ്ഥിരം അക്ഷരം *path, അക്ഷരം *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
അക്ഷരം *
sftp_realpath(സ്ഥിരം അക്ഷരം *path, അക്ഷരം *resolved)
{
	ഘടന stat sb;
	അക്ഷരം *p, *q, *s;
	size_t ഇടത്_len, resolved_len;
	unsigned symlinks;
	പൂർണ്ണസംഖ്യ serrno, slen, mem_allocated;
	അക്ഷരം ഇടത്[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	എങ്കിൽ (path[0] == '\0') {
		errno = ENOENT;
		തിരികെ (ശൂന്യ);
	}

	serrno = errno;

	എങ്കിൽ (resolved == ശൂന്യ) {
		resolved = malloc(PATH_MAX);
		എങ്കിൽ (resolved == ശൂന്യ)
			തിരികെ (ശൂന്യ);
		mem_allocated = 1;
	} അല്ലെങ്കിൽ
		mem_allocated = 0;

	symlinks = 0;
	എങ്കിൽ (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		എങ്കിൽ (path[1] == '\0')
			തിരികെ (resolved);
		resolved_len = 1;
		ഇടത്_len = strlcpy(ഇടത്, path + 1, വലുപ്പം(ഇടത്));
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (getcwd(resolved, PATH_MAX) == ശൂന്യ) {
			എങ്കിൽ (mem_allocated)
				സ്വതന്ത്രം(resolved);
			അല്ലെങ്കിൽ
				strlcpy(resolved, ".", PATH_MAX);
			തിരികെ (ശൂന്യ);
		}
		resolved_len = strlen(resolved);
		ഇടത്_len = strlcpy(ഇടത്, path, വലുപ്പം(ഇടത്));
	}
	എങ്കിൽ (ഇടത്_len >= വലുപ്പം(ഇടത്) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		പോകുക err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ആകുമ്പോൾ (ഇടത്_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ഇടത്, '/');
		s = p ? p : ഇടത് + ഇടത്_len;
		എങ്കിൽ (s - ഇടത് >= (ptrdiff_t)വലുപ്പം(next_token)) {
			errno = ENAMETOOLONG;
			പോകുക err;
		}
		memcpy(next_token, ഇടത്, s - ഇടത്);
		next_token[s - ഇടത്] = '\0';
		ഇടത്_len -= s - ഇടത്;
		എങ്കിൽ (p != ശൂന്യ)
			memmove(ഇടത്, s + 1, ഇടത്_len + 1);
		എങ്കിൽ (resolved[resolved_len - 1] != '/') {
			എങ്കിൽ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				പോകുക err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		എങ്കിൽ (next_token[0] == '\0')
			തുടരുക;
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(next_token, ".") == 0)
			തുടരുക;
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			എങ്കിൽ (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			തുടരുക;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		എങ്കിൽ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			പോകുക err;
		}
		എങ്കിൽ (lstat(resolved, &sb) != 0) {
			എങ്കിൽ (errno == ENOENT && p == ശൂന്യ) {
				errno = serrno;
				തിരികെ (resolved);
			}
			പോകുക err;
		}
		എങ്കിൽ (S_ISLNK(sb.st_mode)) {
			എങ്കിൽ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				പോകുക err;
			}
			slen = readlink(resolved, symlink, വലുപ്പം(symlink) - 1);
			എങ്കിൽ (slen < 0)
				പോകുക err;
			symlink[slen] = '\0';
			എങ്കിൽ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (resolved_len > 1) {
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
			എങ്കിൽ (p != ശൂന്യ) {
				എങ്കിൽ (symlink[slen - 1] != '/') {
					എങ്കിൽ (slen + 1 >=
					    (ptrdiff_t)വലുപ്പം(symlink)) {
						errno = ENAMETOOLONG;
						പോകുക err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ഇടത്_len = strlcat(symlink, ഇടത്, വലുപ്പം(symlink));
				എങ്കിൽ (ഇടത്_len >= വലുപ്പം(symlink)) {
					errno = ENAMETOOLONG;
					പോകുക err;
				}
			}
			ഇടത്_len = strlcpy(ഇടത്, symlink, വലുപ്പം(ഇടത്));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	എങ്കിൽ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	തിരികെ (resolved);

err:
	എങ്കിൽ (mem_allocated)
		സ്വതന്ത്രം(resolved);
	തിരികെ (ശൂന്യ);
}
