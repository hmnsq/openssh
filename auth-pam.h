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

#অন্তর্ভাব "includes.h"
#ifdef USE_PAM

কাঠামো ssh;

শূন্য start_pam(কাঠামো ssh *);
শূন্য finish_pam(শূন্য);
u_int do_pam_account(শূন্য);
শূন্য do_pam_session(কাঠামো ssh *);
শূন্য do_pam_setcred(শূন্য);
পূর্ণসংখ্যা do_pam_putenv(অক্ষর *, অক্ষর *);
অক্ষর ** fetch_pam_environment(শূন্য);
অক্ষর ** fetch_pam_child_environment(শূন্য);
শূন্য free_pam_environment(অক্ষর **);
শূন্য sshpam_thread_cleanup(শূন্য);
শূন্য sshpam_cleanup(শূন্য);
পূর্ণসংখ্যা sshpam_auth_passwd(Authctxt *, ধ্রুবক অক্ষর *);
পূর্ণসংখ্যা sshpam_get_maxtries_reached(শূন্য);
শূন্য sshpam_set_maxtries_reached(পূর্ণসংখ্যা);
পূর্ণসংখ্যা is_pam_session_open(শূন্য);
পূর্ণসংখ্যা sshpam_priv_kbdint_authdone(শূন্য *ctxtp);

#endif /* USE_PAM */
