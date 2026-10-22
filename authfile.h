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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AUTHFILE_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUTHFILE_H

ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

ਪੂਰਨ sshkey_save_ਨਿੱਜੀ(ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);
ਪੂਰਨ sshkey_ਲੱਦੋ_cert(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey **);
ਪੂਰਨ sshkey_ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey **, ਅੱਖਰ **);
ਪੂਰਨ sshkey_ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshkey **, ਅੱਖਰ **);
ਪੂਰਨ sshkey_ਲੱਦੋ_ਨਿੱਜੀ_cert(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਬਣਤਰ sshkey **);
ਪੂਰਨ sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਬਣਤਰ sshkey **, ਅੱਖਰ **);
ਪੂਰਨ sshkey_ਲੱਦੋ_ਨਿੱਜੀ_type_fd(ਪੂਰਨ fd, ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *passphrase,
    ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **commentp);
ਪੂਰਨ sshkey_perm_ok(ਪੂਰਨ, ਅਚਲ ਅੱਖਰ *);
ਪੂਰਨ sshkey_ਵਿੱਚ_file(ਬਣਤਰ sshkey *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ);
ਪੂਰਨ sshkey_check_revoked(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *revoked_ਕੁੰਜੀਆਂ_file);
ਪੂਰਨ sshkey_advance_past_options(ਅੱਖਰ **cpp);
ਪੂਰਨ sshkey_save_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *comment);

#ਜੇ_ਅੰਤ
