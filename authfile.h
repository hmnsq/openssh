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

ساختار sshbuf;
ساختار sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

صحیح sshkey_save_private(ساختار sshkey *, ثابت نویسه *,
    ثابت نویسه *, ثابت نویسه *, صحیح, ثابت نویسه *, صحیح);
صحیح sshkey_load_cert(ثابت نویسه *, ساختار sshkey **);
صحیح sshkey_load_public(ثابت نویسه *, ساختار sshkey **, نویسه **);
صحیح sshkey_load_private(ثابت نویسه *, ثابت نویسه *, ساختار sshkey **, نویسه **);
صحیح sshkey_load_private_cert(صحیح, ثابت نویسه *, ثابت نویسه *,
    ساختار sshkey **);
صحیح sshkey_load_private_type(صحیح, ثابت نویسه *, ثابت نویسه *,
    ساختار sshkey **, نویسه **);
صحیح sshkey_load_private_type_fd(صحیح fd, صحیح type, ثابت نویسه *passphrase,
    ساختار sshkey **keyp, نویسه **commentp);
صحیح sshkey_perm_ok(صحیح, ثابت نویسه *);
صحیح sshkey_in_file(ساختار sshkey *, ثابت نویسه *, صحیح, صحیح);
صحیح sshkey_check_revoked(ساختار sshkey *کلید, ثابت نویسه *revoked_کلیدها_file);
صحیح sshkey_advance_past_options(نویسه **cpp);
صحیح sshkey_save_public(ثابت ساختار sshkey *کلید, ثابت نویسه *path,
    ثابت نویسه *comment);

#endif
