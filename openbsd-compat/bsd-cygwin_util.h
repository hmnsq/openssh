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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _BSD_CYGWIN_UTIL_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _BSD_CYGWIN_UTIL_H

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ERROR

/* Avoid including windows headers. */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ *HANDLE;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INVALID_HANDLE_ਮੁੱਲ ((HANDLE) -1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DNLEN 16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
ਬਾਹਰੀ HANDLE cygwin_logon_user (ਅਚਲ ਬਣਤਰ passwd *, ਅਚਲ ਅੱਖਰ *);
ਬਾਹਰੀ ਖਾਲੀ cygwin_ਸੈੱਟ_impersonation_token (ਅਚਲ HANDLE);

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/cygwin.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <io.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ਅਚਲ ਅੱਖਰ *cygwin_ssh_privsep_user();

ਪੂਰਨ ਦੁਆਧਾਰੀ_open(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ , ...);
ਪੂਰਨ check_ntsec(ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ **fetch_windows_environment(ਖਾਲੀ);
ਖਾਲੀ free_windows_environment(ਅੱਖਰ **);
ਪੂਰਨ cygwin_ug_ਮੇਲ_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ NO_ਦੁਆਧਾਰੀ_OPEN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ open ਦੁਆਧਾਰੀ_open
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* HAVE_CYGWIN */

#ਜੇ_ਅੰਤ /* _BSD_CYGWIN_UTIL_H */
