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

संरचना sshbuf;
संरचना sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

पूर्णांक sshkey_save_private(संरचना sshkey *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *, पूर्णांक, स्थिरांक अक्षर *, पूर्णांक);
पूर्णांक sshkey_load_cert(स्थिरांक अक्षर *, संरचना sshkey **);
पूर्णांक sshkey_load_public(स्थिरांक अक्षर *, संरचना sshkey **, अक्षर **);
पूर्णांक sshkey_load_private(स्थिरांक अक्षर *, स्थिरांक अक्षर *, संरचना sshkey **, अक्षर **);
पूर्णांक sshkey_load_private_cert(पूर्णांक, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    संरचना sshkey **);
पूर्णांक sshkey_load_private_type(पूर्णांक, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    संरचना sshkey **, अक्षर **);
पूर्णांक sshkey_load_private_type_fd(पूर्णांक fd, पूर्णांक type, स्थिरांक अक्षर *passphrase,
    संरचना sshkey **keyp, अक्षर **commentp);
पूर्णांक sshkey_perm_ok(पूर्णांक, स्थिरांक अक्षर *);
पूर्णांक sshkey_in_file(संरचना sshkey *, स्थिरांक अक्षर *, पूर्णांक, पूर्णांक);
पूर्णांक sshkey_check_revoked(संरचना sshkey *किल्ली, स्थिरांक अक्षर *revoked_किल्ल्या_file);
पूर्णांक sshkey_advance_past_options(अक्षर **cpp);
पूर्णांक sshkey_save_public(स्थिरांक संरचना sshkey *किल्ली, स्थिरांक अक्षर *path,
    स्थिरांक अक्षर *comment);

#endif
