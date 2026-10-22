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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _BSD_CYGWIN_UTIL_H
#ವ್ಯಾಖ್ಯಾನಿಸು _BSD_CYGWIN_UTIL_H

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ERROR

/* Avoid including windows headers. */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ *HANDLE;
#ವ್ಯಾಖ್ಯಾನಿಸು INVALID_HANDLE_ಮೌಲ್ಯ ((HANDLE) -1)
#ವ್ಯಾಖ್ಯಾನಿಸು DNLEN 16
#ವ್ಯಾಖ್ಯಾನಿಸು UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
ಬಾಹ್ಯ HANDLE cygwin_logon_user (ಸ್ಥಿರಾಂಕ ರಚನೆ passwd *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಶೂನ್ಯ cygwin_ಗಣ_impersonation_token (ಸ್ಥಿರಾಂಕ HANDLE);

#ಅನ್ತರ್ಭಾವ <sys/cygwin.h>
#ಅನ್ತರ್ಭಾವ <io.h>

#ವ್ಯಾಖ್ಯಾನಿಸು CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cygwin_ssh_privsep_user();

ಪೂರ್ಣಾಂಕ ದ್ವಿಮಾನ_open(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ , ...);
ಪೂರ್ಣಾಂಕ check_ntsec(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ **fetch_windows_environment(ಶೂನ್ಯ);
ಶೂನ್ಯ free_windows_environment(ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ cygwin_ug_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ NO_ದ್ವಿಮಾನ_OPEN
#ವ್ಯಾಖ್ಯಾನಿಸು open ದ್ವಿಮಾನ_open
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CYGWIN */

#ಆದರೆ_ಅಂತ್ಯ /* _BSD_CYGWIN_UTIL_H */
