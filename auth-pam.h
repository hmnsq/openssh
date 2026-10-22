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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM

ರಚನೆ ssh;

ಶೂನ್ಯ ಆರಂಭ_pam(ರಚನೆ ssh *);
ಶೂನ್ಯ ಮುಕ್ತಾಯ_pam(ಶೂನ್ಯ);
u_int do_pam_account(ಶೂನ್ಯ);
ಶೂನ್ಯ do_pam_session(ರಚನೆ ssh *);
ಶೂನ್ಯ do_pam_setcred(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ do_pam_putenv(ಅಕ್ಷರ *, ಅಕ್ಷರ *);
ಅಕ್ಷರ ** fetch_pam_environment(ಶೂನ್ಯ);
ಅಕ್ಷರ ** fetch_pam_ಮಗು_environment(ಶೂನ್ಯ);
ಶೂನ್ಯ free_pam_environment(ಅಕ್ಷರ **);
ಶೂನ್ಯ sshpam_thread_cleanup(ಶೂನ್ಯ);
ಶೂನ್ಯ sshpam_cleanup(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ sshpam_auth_passwd(Authctxt *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ sshpam_get_maxtries_reached(ಶೂನ್ಯ);
ಶೂನ್ಯ sshpam_ಗಣ_maxtries_reached(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ is_pam_session_open(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ sshpam_priv_kbdint_authdone(ಶೂನ್ಯ *ctxtp);

#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */
