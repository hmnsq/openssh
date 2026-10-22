/* $OpenBSD: authfile.h,v 1.25 2020/01/25 23:02:13 djm Exp $ */

/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AUTHFILE_H
#ವ್ಯಾಖ್ಯಾನಿಸು AUTHFILE_H

ರಚನೆ sshbuf;
ರಚನೆ sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

ಪೂರ್ಣಾಂಕ sshkey_save_ಖಾಸಗಿ(ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_cert(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey **, ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshkey **, ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_ಖಾಸಗಿ_cert(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ರಚನೆ sshkey **);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_ಖಾಸಗಿ_type(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    ರಚನೆ sshkey **, ಅಕ್ಷರ **);
ಪೂರ್ಣಾಂಕ sshkey_ತುಂಬು_ಖಾಸಗಿ_type_fd(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *passphrase,
    ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **commentp);
ಪೂರ್ಣಾಂಕ sshkey_perm_ok(ಪೂರ್ಣಾಂಕ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ sshkey_ಒಳ_file(ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ sshkey_check_revoked(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *revoked_ಕೀಲಿಗಳು_file);
ಪೂರ್ಣಾಂಕ sshkey_advance_past_options(ಅಕ್ಷರ **cpp);
ಪೂರ್ಣಾಂಕ sshkey_save_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment);

#ಆದರೆ_ಅಂತ್ಯ
