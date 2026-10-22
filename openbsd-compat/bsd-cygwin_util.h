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

#ifndef _BSD_CYGWIN_UTIL_H
#define _BSD_CYGWIN_UTIL_H

#ifdef HAVE_CYGWIN

#undef ERROR

/* Avoid including windows headers. */
تعریفنوع تهی *HANDLE;
#define INVALID_HANDLE_مقدار ((HANDLE) -1)
#define DNLEN 16
#define UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
بیرونی HANDLE cygwin_logon_user (ثابت ساختار passwd *, ثابت نویسه *);
بیرونی تهی cygwin_set_impersonation_token (ثابت HANDLE);

#شامل <sys/cygwin.h>
#شامل <io.h>

#define CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ثابت نویسه *cygwin_ssh_privsep_user();

صحیح دودویی_open(ثابت نویسه *, صحیح , ...);
صحیح check_ntsec(ثابت نویسه *);
نویسه **fetch_windows_environment(تهی);
تهی free_windows_environment(نویسه **);
صحیح cygwin_ug_match_pattern_list(ثابت نویسه *, ثابت نویسه *);

#ifndef NO_دودویی_OPEN
#define open دودویی_open
#endif

#endif /* HAVE_CYGWIN */

#endif /* _BSD_CYGWIN_UTIL_H */
