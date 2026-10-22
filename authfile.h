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

sa_nracanaa sshbuf;
sa_nracanaa sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

ကိန်းပြည့် sshkey_save_private(sa_nracanaa sshkey *, const var_na *,
    const var_na *, const var_na *, ကိန်းပြည့်, const var_na *, ကိန်းပြည့်);
ကိန်းပြည့် sshkey_load_cert(const var_na *, sa_nracanaa sshkey **);
ကိန်းပြည့် sshkey_load_public(const var_na *, sa_nracanaa sshkey **, var_na **);
ကိန်းပြည့် sshkey_load_private(const var_na *, const var_na *, sa_nracanaa sshkey **, var_na **);
ကိန်းပြည့် sshkey_load_private_cert(ကိန်းပြည့်, const var_na *, const var_na *,
    sa_nracanaa sshkey **);
ကိန်းပြည့် sshkey_load_private_type(ကိန်းပြည့်, const var_na *, const var_na *,
    sa_nracanaa sshkey **, var_na **);
ကိန်းပြည့် sshkey_load_private_type_fd(ကိန်းပြည့် fd, ကိန်းပြည့် type, const var_na *passphrase,
    sa_nracanaa sshkey **keyp, var_na **commentp);
ကိန်းပြည့် sshkey_perm_ok(ကိန်းပြည့်, const var_na *);
ကိန်းပြည့် sshkey_in_file(sa_nracanaa sshkey *, const var_na *, ကိန်းပြည့်, ကိန်းပြည့်);
ကိန်းပြည့် sshkey_check_revoked(sa_nracanaa sshkey *key, const var_na *revoked_keys_file);
ကိန်းပြည့် sshkey_advance_past_options(var_na **cpp);
ကိန်းပြည့် sshkey_save_public(const sa_nracanaa sshkey *key, const var_na *path,
    const var_na *comment);

#endif
