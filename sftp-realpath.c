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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

ଅକ୍ଷର *sftp_realpath(ଅଚଳ ଅକ୍ଷର *path, ଅକ୍ଷର *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
ଅକ୍ଷର *
sftp_realpath(ଅଚଳ ଅକ୍ଷର *path, ଅକ୍ଷର *resolved)
{
	ସଂରଚନା stat sb;
	ଅକ୍ଷର *p, *q, *s;
	size_t ବାମ_len, resolved_len;
	unsigned symlinks;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା serrno, slen, mem_allocated;
	ଅକ୍ଷର ବାମ[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	ଯଦି (path[0] == '\0') {
		errno = ENOENT;
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	serrno = errno;

	ଯଦି (resolved == ଖାଲି) {
		resolved = malloc(PATH_MAX);
		ଯଦି (resolved == ଖାଲି)
			ଫେରନ୍ତୁ (ଖାଲି);
		mem_allocated = 1;
	} ଅନ୍ୟଥା
		mem_allocated = 0;

	symlinks = 0;
	ଯଦି (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ଯଦି (path[1] == '\0')
			ଫେରନ୍ତୁ (resolved);
		resolved_len = 1;
		ବାମ_len = strlcpy(ବାମ, path + 1, ଆକାର(ବାମ));
	} ଅନ୍ୟଥା {
		ଯଦି (getcwd(resolved, PATH_MAX) == ଖାଲି) {
			ଯଦି (mem_allocated)
				ମୁକ୍ତ(resolved);
			ଅନ୍ୟଥା
				strlcpy(resolved, ".", PATH_MAX);
			ଫେରନ୍ତୁ (ଖାଲି);
		}
		resolved_len = strlen(resolved);
		ବାମ_len = strlcpy(ବାମ, path, ଆକାର(ବାମ));
	}
	ଯଦି (ବାମ_len >= ଆକାର(ବାମ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		ଯାଅ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	ଯେତେବେଳେ (ବାମ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ବାମ, '/');
		s = p ? p : ବାମ + ବାମ_len;
		ଯଦି (s - ବାମ >= (ptrdiff_t)ଆକାର(next_token)) {
			errno = ENAMETOOLONG;
			ଯାଅ err;
		}
		memcpy(next_token, ବାମ, s - ବାମ);
		next_token[s - ବାମ] = '\0';
		ବାମ_len -= s - ବାମ;
		ଯଦି (p != ଖାଲି)
			memmove(ବାମ, s + 1, ବାମ_len + 1);
		ଯଦି (resolved[resolved_len - 1] != '/') {
			ଯଦି (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				ଯାଅ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ଯଦି (next_token[0] == '\0')
			ଜାରି;
		ଅନ୍ୟଥା ଯଦି (strcmp(next_token, ".") == 0)
			ଜାରି;
		ଅନ୍ୟଥା ଯଦି (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ଯଦି (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			ଜାରି;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		ଯଦି (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			ଯାଅ err;
		}
		ଯଦି (lstat(resolved, &sb) != 0) {
			ଯଦି (errno == ENOENT && p == ଖାଲି) {
				errno = serrno;
				ଫେରନ୍ତୁ (resolved);
			}
			ଯାଅ err;
		}
		ଯଦି (S_ISLNK(sb.st_mode)) {
			ଯଦି (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				ଯାଅ err;
			}
			slen = readlink(resolved, symlink, ଆକାର(symlink) - 1);
			ଯଦି (slen < 0)
				ଯାଅ err;
			symlink[slen] = '\0';
			ଯଦି (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} ଅନ୍ୟଥା ଯଦି (resolved_len > 1) {
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
			ଯଦି (p != ଖାଲି) {
				ଯଦି (symlink[slen - 1] != '/') {
					ଯଦି (slen + 1 >=
					    (ptrdiff_t)ଆକାର(symlink)) {
						errno = ENAMETOOLONG;
						ଯାଅ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ବାମ_len = strlcat(symlink, ବାମ, ଆକାର(symlink));
				ଯଦି (ବାମ_len >= ଆକାର(symlink)) {
					errno = ENAMETOOLONG;
					ଯାଅ err;
				}
			}
			ବାମ_len = strlcpy(ବାମ, symlink, ଆକାର(ବାମ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ଯଦି (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ଫେରନ୍ତୁ (resolved);

err:
	ଯଦି (mem_allocated)
		ମୁକ୍ତ(resolved);
	ଫେରନ୍ତୁ (ଖାଲି);
}
