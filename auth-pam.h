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

#అన్తర్భావ "includes.h"
#నిర్వచితమైతే USE_PAM

నిర్మాణం ssh;

శూన్య ప్రారంభం_pam(నిర్మాణం ssh *);
శూన్య ముగింపు_pam(శూన్య);
u_int do_pam_account(శూన్య);
శూన్య do_pam_session(నిర్మాణం ssh *);
శూన్య do_pam_setcred(శూన్య);
పూర్ణాంకం do_pam_putenv(అక్షరం *, అక్షరం *);
అక్షరం ** fetch_pam_environment(శూన్య);
అక్షరం ** fetch_pam_బిడ్డ_environment(శూన్య);
శూన్య free_pam_environment(అక్షరం **);
శూన్య sshpam_thread_cleanup(శూన్య);
శూన్య sshpam_cleanup(శూన్య);
పూర్ణాంకం sshpam_auth_passwd(Authctxt *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం sshpam_get_maxtries_reached(శూన్య);
శూన్య sshpam_సమితి_maxtries_reached(పూర్ణాంకం);
పూర్ణాంకం is_pam_session_open(శూన్య);
పూర్ణాంకం sshpam_priv_kbdint_authdone(శూన్య *ctxtp);

#అయితే_ముగింపు /* USE_PAM */
