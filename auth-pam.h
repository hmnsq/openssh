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

#समावेश "includes.h"
#अगर_घोषित USE_PAM

काष्ठा ssh;

व्योम start_pam(काष्ठा ssh *);
व्योम finish_pam(व्योम);
u_int do_pam_account(व्योम);
व्योम do_pam_session(काष्ठा ssh *);
व्योम do_pam_setcred(व्योम);
पूर्णांक do_pam_putenv(अक्षर *, अक्षर *);
अक्षर ** fetch_pam_environment(व्योम);
अक्षर ** fetch_pam_child_environment(व्योम);
व्योम free_pam_environment(अक्षर **);
व्योम sshpam_thread_cleanup(व्योम);
व्योम sshpam_cleanup(व्योम);
पूर्णांक sshpam_auth_passwd(Authctxt *, स्थिर अक्षर *);
पूर्णांक sshpam_get_maxtries_reached(व्योम);
व्योम sshpam_set_maxtries_reached(पूर्णांक);
पूर्णांक is_pam_session_open(व्योम);
पूर्णांक sshpam_priv_kbdint_authdone(व्योम *ctxtp);

#पूर्ण_अगर /* USE_PAM */
