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

கட்டமைப்பு sshbuf;
கட்டமைப்பு sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

முழு sshkey_save_private(கட்டமைப்பு sshkey *, மாறிலி எழுத்து *,
    மாறிலி எழுத்து *, மாறிலி எழுத்து *, முழு, மாறிலி எழுத்து *, முழு);
முழு sshkey_load_cert(மாறிலி எழுத்து *, கட்டமைப்பு sshkey **);
முழு sshkey_load_public(மாறிலி எழுத்து *, கட்டமைப்பு sshkey **, எழுத்து **);
முழு sshkey_load_private(மாறிலி எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு sshkey **, எழுத்து **);
முழு sshkey_load_private_cert(முழு, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    கட்டமைப்பு sshkey **);
முழு sshkey_load_private_type(முழு, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    கட்டமைப்பு sshkey **, எழுத்து **);
முழு sshkey_load_private_type_fd(முழு fd, முழு type, மாறிலி எழுத்து *passphrase,
    கட்டமைப்பு sshkey **keyp, எழுத்து **commentp);
முழு sshkey_perm_ok(முழு, மாறிலி எழுத்து *);
முழு sshkey_in_file(கட்டமைப்பு sshkey *, மாறிலி எழுத்து *, முழு, முழு);
முழு sshkey_check_revoked(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *revoked_சாவிகள்_file);
முழு sshkey_advance_past_options(எழுத்து **cpp);
முழு sshkey_save_public(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *path,
    மாறிலி எழுத்து *comment);

#endif
