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

#که_نه_تعریف_شوی _BSD_CYGWIN_UTIL_H
#تعریف_کړه _BSD_CYGWIN_UTIL_H

#که_تعریف_شوی HAVE_CYGWIN

#تعریف_لغوه ERROR

/* Avoid including windows headers. */
تعريفنوع فراغ *HANDLE;
#تعریف_کړه INVALID_HANDLE_ارزښت ((HANDLE) -1)
#تعریف_کړه DNLEN 16
#تعریف_کړه UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
خارجي HANDLE cygwin_logon_user (ثابت بنية passwd *, ثابت حرف *);
خارجي فراغ cygwin_سېټ_impersonation_token (ثابت HANDLE);

#ضمن <sys/cygwin.h>
#ضمن <io.h>

#تعریف_کړه CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ثابت حرف *cygwin_ssh_privsep_user();

صحيح دوګونی_open(ثابت حرف *, صحيح , ...);
صحيح check_ntsec(ثابت حرف *);
حرف **fetch_windows_environment(فراغ);
فراغ free_windows_environment(حرف **);
صحيح cygwin_ug_سمون_نمونه_list(ثابت حرف *, ثابت حرف *);

#که_نه_تعریف_شوی NO_دوګونی_OPEN
#تعریف_کړه open دوګونی_open
#د_که_پای

#د_که_پای /* HAVE_CYGWIN */

#د_که_پای /* _BSD_CYGWIN_UTIL_H */
