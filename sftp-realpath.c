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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>

#నిర్వచితం_కాకపోతే SYMLOOP_MAX
# define SYMLOOP_MAX 32
#అయితే_ముగింపు

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

అక్షరం *sftp_realpath(స్థిరరాశి అక్షరం *మార్గం, అక్షరం *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
అక్షరం *
sftp_realpath(స్థిరరాశి అక్షరం *మార్గం, అక్షరం *resolved)
{
	నిర్మాణం stat sb;
	అక్షరం *p, *q, *s;
	కొలత_t ఎడమ_len, resolved_len;
	గుర్తులేని symlinks;
	పూర్ణాంకం serrno, slen, mem_allocated;
	అక్షరం ఎడమ[PATH_MAX], తదుపరి_token[PATH_MAX], symlink[PATH_MAX];

	ఒకవేళ (మార్గం[0] == '\0') {
		errno = ENOENT;
		తిరిగి (ఖాళీ);
	}

	serrno = errno;

	ఒకవేళ (resolved == ఖాళీ) {
		resolved = జ్ఞాపకం_ఇవ్వు(PATH_MAX);
		ఒకవేళ (resolved == ఖాళీ)
			తిరిగి (ఖాళీ);
		mem_allocated = 1;
	} లేకపోతే
		mem_allocated = 0;

	symlinks = 0;
	ఒకవేళ (మార్గం[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		ఒకవేళ (మార్గం[1] == '\0')
			తిరిగి (resolved);
		resolved_len = 1;
		ఎడమ_len = strlcpy(ఎడమ, మార్గం + 1, పరిమాణం(ఎడమ));
	} లేకపోతే {
		ఒకవేళ (getcwd(resolved, PATH_MAX) == ఖాళీ) {
			ఒకవేళ (mem_allocated)
				విడుదల(resolved);
			లేకపోతే
				strlcpy(resolved, ".", PATH_MAX);
			తిరిగి (ఖాళీ);
		}
		resolved_len = అక్షరశ్రేణి_పొడవు(resolved);
		ఎడమ_len = strlcpy(ఎడమ, మార్గం, పరిమాణం(ఎడమ));
	}
	ఒకవేళ (ఎడమ_len >= పరిమాణం(ఎడమ) || resolved_len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		వెళ్ళు err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	అయితే (ఎడమ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = strchr(ఎడమ, '/');
		s = p ? p : ఎడమ + ఎడమ_len;
		ఒకవేళ (s - ఎడమ >= (ptrdiff_t)పరిమాణం(తదుపరి_token)) {
			errno = ENAMETOOLONG;
			వెళ్ళు err;
		}
		జ్ఞాపకం_నకలు(తదుపరి_token, ఎడమ, s - ఎడమ);
		తదుపరి_token[s - ఎడమ] = '\0';
		ఎడమ_len -= s - ఎడమ;
		ఒకవేళ (p != ఖాళీ)
			memmove(ఎడమ, s + 1, ఎడమ_len + 1);
		ఒకవేళ (resolved[resolved_len - 1] != '/') {
			ఒకవేళ (resolved_len + 1 >= PATH_MAX) {
				errno = ENAMETOOLONG;
				వెళ్ళు err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		ఒకవేళ (తదుపరి_token[0] == '\0')
			కొనసాగు;
		లేకపోతే ఒకవేళ (strcmp(తదుపరి_token, ".") == 0)
			కొనసాగు;
		లేకపోతే ఒకవేళ (strcmp(తదుపరి_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			ఒకవేళ (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = strrchr(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			కొనసాగు;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, తదుపరి_token, PATH_MAX);
		ఒకవేళ (resolved_len >= PATH_MAX) {
			errno = ENAMETOOLONG;
			వెళ్ళు err;
		}
		ఒకవేళ (lstat(resolved, &sb) != 0) {
			ఒకవేళ (errno == ENOENT && p == ఖాళీ) {
				errno = serrno;
				తిరిగి (resolved);
			}
			వెళ్ళు err;
		}
		ఒకవేళ (S_ISLNK(sb.st_mode)) {
			ఒకవేళ (symlinks++ > SYMLOOP_MAX) {
				errno = ELOOP;
				వెళ్ళు err;
			}
			slen = readlink(resolved, symlink, పరిమాణం(symlink) - 1);
			ఒకవేళ (slen < 0)
				వెళ్ళు err;
			symlink[slen] = '\0';
			ఒకవేళ (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} లేకపోతే ఒకవేళ (resolved_len > 1) {
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
			ఒకవేళ (p != ఖాళీ) {
				ఒకవేళ (symlink[slen - 1] != '/') {
					ఒకవేళ (slen + 1 >=
					    (ptrdiff_t)పరిమాణం(symlink)) {
						errno = ENAMETOOLONG;
						వెళ్ళు err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				ఎడమ_len = strlcat(symlink, ఎడమ, పరిమాణం(symlink));
				ఒకవేళ (ఎడమ_len >= పరిమాణం(symlink)) {
					errno = ENAMETOOLONG;
					వెళ్ళు err;
				}
			}
			ఎడమ_len = strlcpy(ఎడమ, symlink, పరిమాణం(ఎడమ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	ఒకవేళ (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	తిరిగి (resolved);

err:
	ఒకవేళ (mem_allocated)
		విడుదల(resolved);
	తిరిగి (ఖాళీ);
}
