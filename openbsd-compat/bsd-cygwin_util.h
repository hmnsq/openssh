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

#اگر_غیر_تعریف_شدہ _BSD_CYGWIN_UTIL_H
#تعریف_کرو _BSD_CYGWIN_UTIL_H

#اگر_تعریف_شدہ HAVE_CYGWIN

#تعریف_منسوخ ERROR

/* Avoid including windows headers. */
قسمتعریف خالی *HANDLE;
#تعریف_کرو INVALID_HANDLE_قدر ((HANDLE) -1)
#تعریف_کرو DNLEN 16
#تعریف_کرو UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
خارجی HANDLE cygwin_logon_user (ثابت ساخت passwd *, ثابت حرف *);
خارجی خالی cygwin_سیٹ_impersonation_token (ثابت HANDLE);

#شامل <sys/cygwin.h>
#شامل <io.h>

#تعریف_کرو CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ثابت حرف *cygwin_ssh_privsep_user();

صحیح ثنائی_open(ثابت حرف *, صحیح , ...);
صحیح check_ntsec(ثابت حرف *);
حرف **fetch_windows_environment(خالی);
خالی free_windows_environment(حرف **);
صحیح cygwin_ug_مطابقت_نمونہ_list(ثابت حرف *, ثابت حرف *);

#اگر_غیر_تعریف_شدہ NO_ثنائی_OPEN
#تعریف_کرو open ثنائی_open
#اگر_ختم

#اگر_ختم /* HAVE_CYGWIN */

#اگر_ختم /* _BSD_CYGWIN_UTIL_H */
