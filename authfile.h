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

struct sshbuf;
struct sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

целое sshkey_save_private(struct sshkey *, const char *,
    const char *, const char *, целое, const char *, целое);
целое sshkey_load_cert(const char *, struct sshkey **);
целое sshkey_load_public(const char *, struct sshkey **, char **);
целое sshkey_load_private(const char *, const char *, struct sshkey **, char **);
целое sshkey_load_private_cert(целое, const char *, const char *,
    struct sshkey **);
целое sshkey_load_private_type(целое, const char *, const char *,
    struct sshkey **, char **);
целое sshkey_load_private_type_fd(целое fd, целое type, const char *passphrase,
    struct sshkey **keyp, char **commentp);
целое sshkey_perm_ok(целое, const char *);
целое sshkey_in_file(struct sshkey *, const char *, целое, целое);
целое sshkey_check_revoked(struct sshkey *key, const char *revoked_keys_file);
целое sshkey_advance_past_options(char **cpp);
целое sshkey_save_public(const struct sshkey *key, const char *path,
    const char *comment);

#endif
