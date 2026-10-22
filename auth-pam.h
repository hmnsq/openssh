/*
 * Copyright (c) 2000 Damien Miller.  All rights reserved.
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
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM

ਬਣਤਰ ssh;

ਖਾਲੀ ਸ਼ੁਰੂ_pam(ਬਣਤਰ ssh *);
ਖਾਲੀ ਅੰਤ_pam(ਖਾਲੀ);
u_int do_pam_account(ਖਾਲੀ);
ਖਾਲੀ do_pam_session(ਬਣਤਰ ssh *);
ਖਾਲੀ do_pam_setcred(ਖਾਲੀ);
ਪੂਰਨ do_pam_putenv(ਅੱਖਰ *, ਅੱਖਰ *);
ਅੱਖਰ ** fetch_pam_environment(ਖਾਲੀ);
ਅੱਖਰ ** fetch_pam_ਬੱਚਾ_environment(ਖਾਲੀ);
ਖਾਲੀ free_pam_environment(ਅੱਖਰ **);
ਖਾਲੀ sshpam_thread_cleanup(ਖਾਲੀ);
ਖਾਲੀ sshpam_cleanup(ਖਾਲੀ);
ਪੂਰਨ sshpam_auth_passwd(Authctxt *, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ sshpam_get_maxtries_reached(ਖਾਲੀ);
ਖਾਲੀ sshpam_ਸੈੱਟ_maxtries_reached(ਪੂਰਨ);
ਪੂਰਨ is_pam_session_open(ਖਾਲੀ);
ਪੂਰਨ sshpam_priv_kbdint_authdone(ਖਾਲੀ *ctxtp);

#ਜੇ_ਅੰਤ /* USE_PAM */
