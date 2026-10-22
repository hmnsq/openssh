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
வகைவரை வெறுமை *HANDLE;
#define INVALID_HANDLE_மதிப்பு ((HANDLE) -1)
#define DNLEN 16
#define UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
வெளி HANDLE cygwin_logon_user (மாறிலி கட்டமைப்பு passwd *, மாறிலி எழுத்து *);
வெளி வெறுமை cygwin_set_impersonation_token (மாறிலி HANDLE);

#அந்தர்பாவ <sys/cygwin.h>
#அந்தர்பாவ <io.h>

#define CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
மாறிலி எழுத்து *cygwin_ssh_privsep_user();

முழு இருமம்_open(மாறிலி எழுத்து *, முழு , ...);
முழு check_ntsec(மாறிலி எழுத்து *);
எழுத்து **fetch_windows_environment(வெறுமை);
வெறுமை free_windows_environment(எழுத்து **);
முழு cygwin_ug_match_pattern_list(மாறிலி எழுத்து *, மாறிலி எழுத்து *);

#ifndef NO_இருமம்_OPEN
#define open இருமம்_open
#endif

#endif /* HAVE_CYGWIN */

#endif /* _BSD_CYGWIN_UTIL_H */
