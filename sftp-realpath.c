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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <stddef.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <limits.h>

#अगर_अघोषित SYMLOOP_MAX
# define SYMLOOP_MAX 32
#पूर्ण_अगर

/* XXX rewrite sftp-server to use POSIX realpath and remove this hack */

अक्षर *sftp_realpath(स्थिर अक्षर *path, अक्षर *resolved);

/*
 * char *realpath(const char *path, char resolved[PATH_MAX]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
अक्षर *
sftp_realpath(स्थिर अक्षर *path, अक्षर *resolved)
{
	काष्ठा stat sb;
	अक्षर *p, *q, *s;
	माप_प्रकार बायाँ_len, resolved_len;
	अचिन्हित symlinks;
	पूर्णांक serrno, slen, mem_allocated;
	अक्षर बायाँ[PATH_MAX], अग्र_token[PATH_MAX], symlink[PATH_MAX];

	अगर (path[0] == '\0') {
		त्रुटि_सं = ENOENT;
		वापस (शून्य);
	}

	serrno = त्रुटि_सं;

	अगर (resolved == शून्य) {
		resolved = दो_स्मृति(PATH_MAX);
		अगर (resolved == शून्य)
			वापस (शून्य);
		mem_allocated = 1;
	} अन्यथा
		mem_allocated = 0;

	symlinks = 0;
	अगर (path[0] == '/') {
		resolved[0] = '/';
		resolved[1] = '\0';
		अगर (path[1] == '\0')
			वापस (resolved);
		resolved_len = 1;
		बायाँ_len = strlcpy(बायाँ, path + 1, माप(बायाँ));
	} अन्यथा {
		अगर (getcwd(resolved, PATH_MAX) == शून्य) {
			अगर (mem_allocated)
				मुक्त(resolved);
			अन्यथा
				strlcpy(resolved, ".", PATH_MAX);
			वापस (शून्य);
		}
		resolved_len = म_माप(resolved);
		बायाँ_len = strlcpy(बायाँ, path, माप(बायाँ));
	}
	अगर (बायाँ_len >= माप(बायाँ) || resolved_len >= PATH_MAX) {
		त्रुटि_सं = ENAMETOOLONG;
		जाओ err;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	जबतक (बायाँ_len != 0) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		p = म_अक्षर(बायाँ, '/');
		s = p ? p : बायाँ + बायाँ_len;
		अगर (s - बायाँ >= (सूचक_भेद_प्रकार)माप(अग्र_token)) {
			त्रुटि_सं = ENAMETOOLONG;
			जाओ err;
		}
		स_नकल(अग्र_token, बायाँ, s - बायाँ);
		अग्र_token[s - बायाँ] = '\0';
		बायाँ_len -= s - बायाँ;
		अगर (p != शून्य)
			स_हटाओ(बायाँ, s + 1, बायाँ_len + 1);
		अगर (resolved[resolved_len - 1] != '/') {
			अगर (resolved_len + 1 >= PATH_MAX) {
				त्रुटि_सं = ENAMETOOLONG;
				जाओ err;
			}
			resolved[resolved_len++] = '/';
			resolved[resolved_len] = '\0';
		}
		अगर (अग्र_token[0] == '\0')
			जारी;
		अन्यथा अगर (म_भेद(अग्र_token, ".") == 0)
			जारी;
		अन्यथा अगर (म_भेद(अग्र_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			अगर (resolved_len > 1) {
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
		resolved_len = strlcat(resolved, अग्र_token, PATH_MAX);
		अगर (resolved_len >= PATH_MAX) {
			त्रुटि_सं = ENAMETOOLONG;
			जाओ err;
		}
		अगर (lstat(resolved, &sb) != 0) {
			अगर (त्रुटि_सं == ENOENT && p == शून्य) {
				त्रुटि_सं = serrno;
				वापस (resolved);
			}
			जाओ err;
		}
		अगर (S_ISLNK(sb.st_mode)) {
			अगर (symlinks++ > SYMLOOP_MAX) {
				त्रुटि_सं = ELOOP;
				जाओ err;
			}
			slen = readlink(resolved, symlink, माप(symlink) - 1);
			अगर (slen < 0)
				जाओ err;
			symlink[slen] = '\0';
			अगर (symlink[0] == '/') {
				resolved[1] = 0;
				resolved_len = 1;
			} अन्यथा अगर (resolved_len > 1) {
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
			अगर (p != शून्य) {
				अगर (symlink[slen - 1] != '/') {
					अगर (slen + 1 >=
					    (सूचक_भेद_प्रकार)माप(symlink)) {
						त्रुटि_सं = ENAMETOOLONG;
						जाओ err;
					}
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
				बायाँ_len = strlcat(symlink, बायाँ, माप(symlink));
				अगर (बायाँ_len >= माप(symlink)) {
					त्रुटि_सं = ENAMETOOLONG;
					जाओ err;
				}
			}
			बायाँ_len = strlcpy(बायाँ, symlink, माप(बायाँ));
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	अगर (resolved_len > 1 && resolved[resolved_len - 1] == '/')
		resolved[resolved_len - 1] = '\0';
	वापस (resolved);

err:
	अगर (mem_allocated)
		मुक्त(resolved);
	वापस (शून्य);
}
