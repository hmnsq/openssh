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

#அந்தர்பாவ "includes.h"
#ifdef USE_PAM

கட்டமைப்பு ssh;

வெறுமை start_pam(கட்டமைப்பு ssh *);
வெறுமை finish_pam(வெறுமை);
u_int do_pam_account(வெறுமை);
வெறுமை do_pam_session(கட்டமைப்பு ssh *);
வெறுமை do_pam_setcred(வெறுமை);
முழு do_pam_putenv(எழுத்து *, எழுத்து *);
எழுத்து ** fetch_pam_environment(வெறுமை);
எழுத்து ** fetch_pam_child_environment(வெறுமை);
வெறுமை free_pam_environment(எழுத்து **);
வெறுமை sshpam_thread_cleanup(வெறுமை);
வெறுமை sshpam_cleanup(வெறுமை);
முழு sshpam_auth_passwd(Authctxt *, மாறிலி எழுத்து *);
முழு sshpam_get_maxtries_reached(வெறுமை);
வெறுமை sshpam_set_maxtries_reached(முழு);
முழு is_pam_session_open(வெறுமை);
முழு sshpam_priv_kbdint_authdone(வெறுமை *ctxtp);

#endif /* USE_PAM */
