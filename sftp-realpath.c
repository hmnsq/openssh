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

अक्षर *sftp_realpath(स्थिरांक अक्षर *path, अक्षर *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
अक्षर *
sftp_realpath(स्थिरांक अक्षर *path, अक्षर *resolved)
{
	संरचना stat sb;
	अक्षर *p, *q, *s;
	माप_प्रकार डावा_len, resolved_len;
	अचिन्हित symlinks;
	पूर्णांक serrno, slen, mem_allocated;
	अक्षर डावा[PATH_MAX], next_token[PATH_MAX], symlink[PATH_MAX];

	जर (path[0] == '\0') {
		त्रुटि_सं = ENOENT;
		परत (रिक्त);
	}

	serrno = त्रुटि_सं;

	जर (resolved == रिक्त) {
		resolved = दो_स्मृति(PATH_MAX);
		जर (resolved == रिक्त)
			परत (रिक्त);
		mem_allocated = 1;
	} अन्यथा
		mem_allocated = 0;

	symlinks = 0;
	जर (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		जर (path[1] == '\0')
			परत (resolved);
		resolved_len = 1;
		डावा_len = strlcpy(डावा, path + 1, आकार(डावा));
	} अन्यथा {
		जर (getcwd(resolved, PATH_MAX) == रिक्त) {
			जर (mem_allocated)
				मुक्त(resolved);
			अन्यथा
				strlcpy(resolved, ".", PATH_MAX);
			परत (रिक्त);
		}
		resolved_len = म_माप(resolved);
		डावा_len = strlcpy(डावा, path, आकार(डावा));
	}
	जर (डावा_len >= आकार(डावा) || resolved_len >= PATH_MAX) {
		त्रुटि_सं = ENAMETOOLONG;
		जा err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	पर्यंत (डावा_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = म_अक्षर(डावा, '/');
		s = p ? p : डावा + डावा_len;
		जर (s - डावा >= (सूचक_भेद_प्रकार)आकार(next_token)) {
			त्रुटि_सं = ENAMETOOLONG;
			जा err;
		}
		स_नकल(next_token, डावा, s - डावा);
		next_token[s - डावा] = '\0';
		डावा_len -= s - डावा;
		जर (p != रिक्त)
			स_हटाओ(डावा, s + 1, डावा_len + 1);
		जर (resolved[resolved_len - 1] != '/') {
			जर (resolved_len + 1 >= PATH_MAX) {
				त्रुटि_सं = ENAMETOOLONG;
				जा err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		जर (next_token[0] == '\0')
			सुरूठेवा;
		अन्यथा जर (म_भेद(next_token, ".") == 0)
			सुरूठेवा;
		अन्यथा जर (म_भेद(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			जर (resolved_len > 1) {
				resolved[resolved_len - 1] = '\0';
				q = म_खोजप(resolved, '/') + 1;
				*q = '\0';
				resolved_len = q - resolved;
			}
			सुरूठेवा;
		}

		/*
		 * Append the next path component and lstat() it. If
		 * lstat() fails we still can return successfully if
		 * there are no more path components left.
		 */
		resolved_len = strlcat(resolved, next_token, PATH_MAX);
		जर (resolved_len >= PATH_MAX) {
			त्रुटि_सं = ENAMETOOLONG;
			जा err;
		}
		जर (lstat(resolved, &sb) != 0) {
			जर (त्रुटि_सं == ENOENT && p == रिक्त) {
				त्रुटि_सं = serrno;
				परत (resolved);
			}
			जा err;
		}
		जर (S_ISLNK(sb.st_mode)) {
			जर (symlinks++ > SYMLOOP_MAX) {
				त्रुटि_सं = ELOOP;
				जा err;
			}
			slen = readlink(resolved, symlink, आकार(symlink) - 1);
			जर (slen < 0)
				जा err;
			symlink[slen] = '\0';
			जर (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} अन्यथा जर (resolved_len > 1) {
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
			जर (p != रिक्त) {
				जर (symlink[slen - 1] != '/') {
					जर (slen + 1 >=
					    (सूचक_भेद_प्रकार)आकार(symlink)) {
						त्रुटि_सं = ENAMETOOLONG;
						जा err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				डावा_len = strlcat(symlink, डावा, आकार(symlink));
				जर (डावा_len >= आकार(symlink)) {
					त्रुटि_सं = ENAMETOOLONG;
					जा err;
				}
			}
			डावा_len = strlcpy(डावा, symlink, आकार(डावा));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	जर (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	परत (resolved);

err:
	जर (mem_allocated)
		मुक्त(resolved);
	परत (रिक्त);
}
