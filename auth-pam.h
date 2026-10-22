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

#അന്തര്ഭാവ "includes.h"
#ifdef USE_PAM

ഘടന ssh;

ശൂന്യം start_pam(ഘടന ssh *);
ശൂന്യം finish_pam(ശൂന്യം);
u_int do_pam_account(ശൂന്യം);
ശൂന്യം do_pam_session(ഘടന ssh *);
ശൂന്യം do_pam_setcred(ശൂന്യം);
പൂർണ്ണസംഖ്യ do_pam_putenv(അക്ഷരം *, അക്ഷരം *);
അക്ഷരം ** fetch_pam_environment(ശൂന്യം);
അക്ഷരം ** fetch_pam_child_environment(ശൂന്യം);
ശൂന്യം free_pam_environment(അക്ഷരം **);
ശൂന്യം sshpam_thread_cleanup(ശൂന്യം);
ശൂന്യം sshpam_cleanup(ശൂന്യം);
പൂർണ്ണസംഖ്യ sshpam_auth_passwd(Authctxt *, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ sshpam_get_maxtries_reached(ശൂന്യം);
ശൂന്യം sshpam_set_maxtries_reached(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ is_pam_session_open(ശൂന്യം);
പൂർണ്ണസംഖ്യ sshpam_priv_kbdint_authdone(ശൂന്യം *ctxtp);

#endif /* USE_PAM */
