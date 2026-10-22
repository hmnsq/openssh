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

#ضمن "includes.h"
#جے_تعریف_شدہ USE_PAM

بنية ssh;

فراغ شروع_pam(بنية ssh *);
فراغ انت_pam(فراغ);
u_int do_pam_account(فراغ);
فراغ do_pam_session(بنية ssh *);
فراغ do_pam_setcred(فراغ);
صحيح do_pam_putenv(حرف *, حرف *);
حرف ** fetch_pam_environment(فراغ);
حرف ** fetch_pam_بچہ_environment(فراغ);
فراغ free_pam_environment(حرف **);
فراغ sshpam_thread_cleanup(فراغ);
فراغ sshpam_cleanup(فراغ);
صحيح sshpam_auth_passwd(Authctxt *, ثابت حرف *);
صحيح sshpam_get_maxtries_reached(فراغ);
فراغ sshpam_سیٹ_maxtries_reached(صحيح);
صحيح is_pam_session_open(فراغ);
صحيح sshpam_priv_kbdint_authdone(فراغ *ctxtp);

#جے_انت /* USE_PAM */
