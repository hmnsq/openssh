/*
 * Copyright (c) 2000, 2001, 2011, 2013 Corinna Vinschen <vinschen@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Created: Sat Sep 02 12:17:00 2000 cv
 *
 * This file contains functions for forcing opened file descriptors to
 * binary mode on Windows systems.
 */

#अगर_अघोषित _BSD_CYGWIN_UTIL_H
#घोषणा _BSD_CYGWIN_UTIL_H

#अगर_घोषित HAVE_CYGWIN

#अघोषित ERROR

/* Avoid including windows headers. */
प्रकार व्योम *HANDLE;
#घोषणा INVALID_HANDLE_मूल्य ((HANDLE) -1)
#घोषणा DNLEN 16
#घोषणा UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
बाह्य HANDLE cygwin_logon_user (स्थिर काष्ठा passwd *, स्थिर अक्षर *);
बाह्य व्योम cygwin_set_impersonation_token (स्थिर HANDLE);

#समावेश <sys/cygwin.h>
#समावेश <io.h>

#घोषणा CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
स्थिर अक्षर *cygwin_ssh_privsep_user();

पूर्णांक द्विआधारी_open(स्थिर अक्षर *, पूर्णांक , ...);
पूर्णांक check_ntsec(स्थिर अक्षर *);
अक्षर **fetch_windows_environment(व्योम);
व्योम free_windows_environment(अक्षर **);
पूर्णांक cygwin_ug_match_pattern_list(स्थिर अक्षर *, स्थिर अक्षर *);

#अगर_अघोषित NO_द्विआधारी_OPEN
#घोषणा खोलो द्विआधारी_open
#पूर्ण_अगर

#पूर्ण_अगर /* HAVE_CYGWIN */

#पूर्ण_अगर /* _BSD_CYGWIN_UTIL_H */
