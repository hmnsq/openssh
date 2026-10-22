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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>

#ifndef SYMLOOP_MAX
# define SYMLOOP_MAX 32
#endif

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

वर्ण *sftp_realpath(अचर वर्ण *path, वर्ण *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
वर्ण *
sftp_realpath(अचर वर्ण *path, वर्ण *resolved)
{
	संरचना stat sb;
	वर्ण *p, *q, *s;
	माप_प्रकार बायाँ_len, resolved_len;
	अचिन्हित symlinks;
	पूर्णाङ्क serrno, slen, mem_allocated;
	वर्ण बायाँ[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	यदि (path[0] == '\0') {
		त्रुटि_सं = ENOENT;
		फर्काऊ (रिक्त);
	}

	serrno = त्रुटि_सं;

	यदि (resolved == रिक्त) {
		resolved = दो_स्मृति(PATH_MAX);
		यदि (resolved == रिक्त)
			फर्काऊ (रिक्त);
		mem_allocated = 1;
	} अन्यथा
		mem_allocated = 0;

	symlinks = 0;
	यदि (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		यदि (path[1] == '\0')
			फर्काऊ (resolved);
		resolved_len = 1;
		बायाँ_len = strlcpy(बायाँ, path + 1, परिमाण(बायाँ));
	} अन्यथा {
		यदि (getcwd(resolved, PATH_MAX) == रिक्त) {
			यदि (mem_allocated)
				मुक्त(resolved);
			अन्यथा
				strlcpy(resolved, ".", PATH_MAX);
			फर्काऊ (रिक्त);
		}
		resolved_len = म_माप(resolved);
		बायाँ_len = strlcpy(बायाँ, path, परिमाण(बायाँ));
	}
	यदि (बायाँ_len >= परिमाण(बायाँ) || resolved_len >= PATH_MAX) {
		त्रुटि_सं = ENAMETOOLONG;
		गच्छ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	जबसम्म (बायाँ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = म_अक्षर(बायाँ, '/');
		s = p ? p : बायाँ + बायाँ_len;
		यदि (s - बायाँ >= (सूचक_भेद_प्रकार)परिमाण(next_token)) {
			त्रुटि_सं = ENAMETOOLONG;
			गच्छ err;
		}
		स_नकल(next_token, बायाँ, s - बायाँ);
		next_token[s - बायाँ] = '\0';
		बायाँ_len -= s - बायाँ;
		यदि (p != रिक्त)
			स_हटाओ(बायाँ, s + 1, बायाँ_len + 1);
		यदि (resolved[resolved_len - 1] != '/') {
			यदि (resolved_len + 1 >= PATH_MAX) {
				त्रुटि_सं = ENAMETOOLONG;
				गच्छ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		यदि (next_token[0] == '\0')
			जारी;
		अन्यथा यदि (म_भेद(next_token, ".") == 0)
			जारी;
		अन्यथा यदि (म_भेद(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			यदि (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = म_खोजप(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			जारी;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		यदि (resolved_len >= PATH_MAX) {
			त्रुटि_सं = ENAMETOOLONG;
			गच्छ err;
		}
		यदि (lstat(resolved, &sb) != 0) {
			यदि (त्रुटि_सं == ENOENT && p == रिक्त) {
				त्रुटि_सं = serrno;
				फर्काऊ (resolved);
			}
			गच्छ err;
		}
		यदि (S_ISLNK(sb.st_mode)) {
			यदि (symlinks++ > SYMLOOP_MAX) {
				त्रुटि_सं = ELOOP;
				गच्छ err;
			}
			slen = readlink(resolved, symlink, परिमाण(symlink) - 1);
			यदि (slen < 0)
				गच्छ err;
			symlink[slen] = '\0';
			यदि (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} अन्यथा यदि (resolved_len > 1) {
				/* Strip the last path component. */
				resolved[resolved_len - 1] = '\0';
				q = म_खोजप(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}

			/*
			 * If there are any path components left, then
			 * append them to symlink. The result is placed
			 * in `left'.
			 */
			यदि (p != रिक्त) {
				यदि (symlink[slen - 1] != '/') {
					यदि (slen + 1 >=
					    (सूचक_भेद_प्रकार)परिमाण(symlink)) {
						त्रुटि_सं = ENAMETOOLONG;
						गच्छ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				बायाँ_len = strlcat(symlink, बायाँ, परिमाण(symlink));
				यदि (बायाँ_len >= परिमाण(symlink)) {
					त्रुटि_सं = ENAMETOOLONG;
					गच्छ err;
				}
			}
			बायाँ_len = strlcpy(बायाँ, symlink, परिमाण(बायाँ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	यदि (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	फर्काऊ (resolved);

err:
	यदि (mem_allocated)
		मुक्त(resolved);
	फर्काऊ (रिक्त);
}
