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

#ifndef AUTHFILE_H
#define AUTHFILE_H

ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

ಪೂರ್ಣಾಙ್ಕ sshkey_save_private(ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *,
    ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_cert(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey **);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_public(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey **, ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_private(ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshkey **, ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_private_cert(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಸಂರಚನಾ sshkey **);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_private_type(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    ಸಂರಚನಾ sshkey **, ವರ್ಣ **);
ಪೂರ್ಣಾಙ್ಕ sshkey_load_private_type_fd(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *passphrase,
    ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **commentp);
ಪೂರ್ಣಾಙ್ಕ sshkey_perm_ok(ಪೂರ್ಣಾಙ್ಕ, ಧ್ರುವ ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ sshkey_in_file(ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ sshkey_check_revoked(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *revoked_ಕೀಲಿಗಳು_file);
ಪೂರ್ಣಾಙ್ಕ sshkey_advance_past_options(ವರ್ಣ **cpp);
ಪೂರ್ಣಾಙ್ಕ sshkey_save_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *path,
    ಧ್ರುವ ವರ್ಣ *comment);

#endif
