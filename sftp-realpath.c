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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

ৱর্ণ *sftp_realpath(ধ্রুৱ ৱর্ণ *path, ৱর্ণ *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
ৱর্ণ *
sftp_realpath(ধ্রুৱ ৱর্ণ *path, ৱর্ণ *resolved)
{
	সংরচনা stat sb;
	ৱর্ণ *p, *q, *s;
	size_t বাম_len, resolved_len;
	unsigned symlinks;
	পূর্ণাঙ্ক serrno, slen, mem_allocated;
	ৱর্ণ বাম[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	যদি (path[0] == '\0') {
		errno = ENOENT;
		ঘূৰাই (রিক্ত);
	}

	serrno = errno;

	যদি (resolved == রিক্ত) {
		resolved = malloc(PATH_MAX);
		যদি (resolved == রিক্ত)
			ঘূৰাই (রিক্ত);
		mem_allocated = 1;
	} অন্যথা
		mem_allocated = 0;

	symlinks = 0;
	যদি (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		যদি (path[1] == '\0')
			ঘূৰাই (resolved);
		resolved_len = 1;
		বাম_len = strlcpy(বাম, path + 1, পরিমাণ(বাম));
	} অন্যথা {
		যদি (getcwd(resolved, PATH_MAX) == রিক্ত) {
			যদি (mem_allocated)
				মুক্ত(resolved);
			অন্যথা
				strlcpy(resolved, ".", PATH_MAX);
			ঘূৰাই (রিক্ত);
		}
		resolved_len = strlen(resolved);
		বাম_len = strlcpy(বাম, path, পরিমাণ(বাম));
	}
	যদি (বাম_len >= পরিমাণ(বাম) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		গচ্ছ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	যেতিয়ালৈ (বাম_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(বাম, '/');
		s = p ? p : বাম + বাম_len;
		যদি (s - বাম >= (ptrdiff_t)পরিমাণ(next_token)) {
			errno = ENAMETOOLONG;
			গচ্ছ err;
		}
		memcpy(next_token, বাম, s - বাম);
		next_token[s - বাম] = '\0';
		বাম_len -= s - বাম;
		যদি (p != রিক্ত)
			memmove(বাম, s + 1, বাম_len + 1);
		যদি (resolved[resolved_len - 1] != '/') {
			যদি (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				গচ্ছ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		যদি (next_token[0] == '\0')
			অনুৱর্ত;
		অন্যথা যদি (strcmp(next_token, ".") == 0)
			অনুৱর্ত;
		অন্যথা যদি (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			যদি (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			অনুৱর্ত;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		যদি (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			গচ্ছ err;
		}
		যদি (lstat(resolved, &sb) != 0) {
			যদি (errno == ENOENT && p == রিক্ত) {
				errno = serrno;
				ঘূৰাই (resolved);
			}
			গচ্ছ err;
		}
		যদি (S_ISLNK(sb.st_mode)) {
			যদি (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				গচ্ছ err;
			}
			slen = readlink(resolved, symlink, পরিমাণ(symlink) - 1);
			যদি (slen < 0)
				গচ্ছ err;
			symlink[slen] = '\0';
			যদি (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} অন্যথা যদি (resolved_len > 1) {
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
			যদি (p != রিক্ত) {
				যদি (symlink[slen - 1] != '/') {
					যদি (slen + 1 >=
					    (ptrdiff_t)পরিমাণ(symlink)) {
						errno = ENAMETOOLONG;
						গচ্ছ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				বাম_len = strlcat(symlink, বাম, পরিমাণ(symlink));
				যদি (বাম_len >= পরিমাণ(symlink)) {
					errno = ENAMETOOLONG;
					গচ্ছ err;
				}
			}
			বাম_len = strlcpy(বাম, symlink, পরিমাণ(বাম));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	যদি (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	ঘূৰাই (resolved);

err:
	যদি (mem_allocated)
		মুক্ত(resolved);
	ঘূৰাই (রিক্ত);
}
