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

সংরচনা sshbuf;
সংরচনা sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

পূর্ণাঙ্ক sshkey_save_private(সংরচনা sshkey *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক, ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক sshkey_load_cert(ধ্রুব বর্ণ *, সংরচনা sshkey **);
পূর্ণাঙ্ক sshkey_load_public(ধ্রুব বর্ণ *, সংরচনা sshkey **, বর্ণ **);
পূর্ণাঙ্ক sshkey_load_private(ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, সংরচনা sshkey **, বর্ণ **);
পূর্ণাঙ্ক sshkey_load_private_cert(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *,
    সংরচনা sshkey **);
পূর্ণাঙ্ক sshkey_load_private_type(পূর্ণাঙ্ক, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *,
    সংরচনা sshkey **, বর্ণ **);
পূর্ণাঙ্ক sshkey_load_private_type_fd(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক type, ধ্রুব বর্ণ *passphrase,
    সংরচনা sshkey **keyp, বর্ণ **commentp);
পূর্ণাঙ্ক sshkey_perm_ok(পূর্ণাঙ্ক, ধ্রুব বর্ণ *);
পূর্ণাঙ্ক sshkey_in_file(সংরচনা sshkey *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক sshkey_check_revoked(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *revoked_চাবিগুলি_file);
পূর্ণাঙ্ক sshkey_advance_past_options(বর্ণ **cpp);
পূর্ণাঙ্ক sshkey_save_public(ধ্রুব সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *path,
    ধ্রুব বর্ণ *comment);

#endif
