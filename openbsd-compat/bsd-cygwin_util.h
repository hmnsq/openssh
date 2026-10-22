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

#यदि_अपरिभाषितम् _BSD_CYGWIN_UTIL_H
#परिभाषय _BSD_CYGWIN_UTIL_H

#यदि_परिभाषितम् HAVE_CYGWIN

#अपरिभाषय ERROR

/* Avoid including windows headers. */
प्रकारनिर्देश शून्य *HANDLE;
#परिभाषय INVALID_HANDLE_मानम् ((HANDLE) -1)
#परिभाषय DNLEN 16
#परिभाषय UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
बाह्य HANDLE cygwin_logon_user (ध्रुव संरचना passwd *, ध्रुव वर्ण *);
बाह्य शून्य cygwin_समुच्चयः_impersonation_token (ध्रुव HANDLE);

#अन्तर्भाव <sys/cygwin.h>
#अन्तर्भाव <io.h>

#परिभाषय CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ध्रुव वर्ण *cygwin_ssh_privsep_user();

पूर्णाङ्क द्विमान_open(ध्रुव वर्ण *, पूर्णाङ्क , ...);
पूर्णाङ्क check_ntsec(ध्रुव वर्ण *);
वर्ण **fetch_windows_environment(शून्य);
शून्य free_windows_environment(वर्ण **);
पूर्णाङ्क cygwin_ug_मेलनम्_आदर्शः_list(ध्रुव वर्ण *, ध्रुव वर्ण *);

#यदि_अपरिभाषितम् NO_द्विमान_OPEN
#परिभाषय उद्घाटय द्विमान_open
#यदि_अन्तः

#यदि_अन्तः /* HAVE_CYGWIN */

#यदि_अन्तः /* _BSD_CYGWIN_UTIL_H */
