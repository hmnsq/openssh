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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifdef USE_PAM

ସଂରଚନା ssh;

ଶୂନ୍ୟ start_pam(ସଂରଚନା ssh *);
ଶୂନ୍ୟ finish_pam(ଶୂନ୍ୟ);
u_int do_pam_account(ଶୂନ୍ୟ);
ଶୂନ୍ୟ do_pam_session(ସଂରଚନା ssh *);
ଶୂନ୍ୟ do_pam_setcred(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_pam_putenv(ଅକ୍ଷର *, ଅକ୍ଷର *);
ଅକ୍ଷର ** fetch_pam_environment(ଶୂନ୍ୟ);
ଅକ୍ଷର ** fetch_pam_child_environment(ଶୂନ୍ୟ);
ଶୂନ୍ୟ free_pam_environment(ଅକ୍ଷର **);
ଶୂନ୍ୟ sshpam_thread_cleanup(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshpam_cleanup(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_auth_passwd(Authctxt *, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_get_maxtries_reached(ଶୂନ୍ୟ);
ଶୂନ୍ୟ sshpam_set_maxtries_reached(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_pam_session_open(ଶୂନ୍ୟ);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshpam_priv_kbdint_authdone(ଶୂନ୍ୟ *ctxtp);

#endif /* USE_PAM */
