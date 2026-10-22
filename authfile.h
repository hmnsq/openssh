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

#اگر_تعریف_نشده AUTHFILE_H
#تعریف_کن AUTHFILE_H

بنية sshbuf;
بنية sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

صحيح sshkey_save_خصوصی(بنية sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, صحيح, ثابت حرف *, صحيح);
صحيح sshkey_بارگیری_cert(ثابت حرف *, بنية sshkey **);
صحيح sshkey_بارگیری_عمومی(ثابت حرف *, بنية sshkey **, حرف **);
صحيح sshkey_بارگیری_خصوصی(ثابت حرف *, ثابت حرف *, بنية sshkey **, حرف **);
صحيح sshkey_بارگیری_خصوصی_cert(صحيح, ثابت حرف *, ثابت حرف *,
    بنية sshkey **);
صحيح sshkey_بارگیری_خصوصی_type(صحيح, ثابت حرف *, ثابت حرف *,
    بنية sshkey **, حرف **);
صحيح sshkey_بارگیری_خصوصی_type_fd(صحيح fd, صحيح type, ثابت حرف *passphrase,
    بنية sshkey **keyp, حرف **commentp);
صحيح sshkey_perm_ok(صحيح, ثابت حرف *);
صحيح sshkey_درون_file(بنية sshkey *, ثابت حرف *, صحيح, صحيح);
صحيح sshkey_check_revoked(بنية sshkey *کلید, ثابت حرف *revoked_کلیدها_file);
صحيح sshkey_advance_past_options(حرف **cpp);
صحيح sshkey_save_عمومی(ثابت بنية sshkey *کلید, ثابت حرف *مسیر,
    ثابت حرف *comment);

#پایان_اگر
