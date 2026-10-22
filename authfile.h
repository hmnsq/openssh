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

#اگر_غیر_تعریف_شدہ AUTHFILE_H
#تعریف_کرو AUTHFILE_H

ساخت sshbuf;
ساخت sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

صحیح sshkey_save_نجی(ساخت sshkey *, ثابت حرف *,
    ثابت حرف *, ثابت حرف *, صحیح, ثابت حرف *, صحیح);
صحیح sshkey_بھرو_cert(ثابت حرف *, ساخت sshkey **);
صحیح sshkey_بھرو_عوامی(ثابت حرف *, ساخت sshkey **, حرف **);
صحیح sshkey_بھرو_نجی(ثابت حرف *, ثابت حرف *, ساخت sshkey **, حرف **);
صحیح sshkey_بھرو_نجی_cert(صحیح, ثابت حرف *, ثابت حرف *,
    ساخت sshkey **);
صحیح sshkey_بھرو_نجی_type(صحیح, ثابت حرف *, ثابت حرف *,
    ساخت sshkey **, حرف **);
صحیح sshkey_بھرو_نجی_type_fd(صحیح fd, صحیح type, ثابت حرف *passphrase,
    ساخت sshkey **keyp, حرف **commentp);
صحیح sshkey_perm_ok(صحیح, ثابت حرف *);
صحیح sshkey_اندر_file(ساخت sshkey *, ثابت حرف *, صحیح, صحیح);
صحیح sshkey_check_revoked(ساخت sshkey *کلید, ثابت حرف *revoked_کلیدیں_file);
صحیح sshkey_advance_past_options(حرف **cpp);
صحیح sshkey_save_عوامی(ثابت ساخت sshkey *کلید, ثابت حرف *راستہ,
    ثابت حرف *comment);

#اگر_ختم
