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

पूर्णाङ्क sshkey_save_private(संरचना sshkey *, अचर वर्ण *,
    अचर वर्ण *, अचर वर्ण *, पूर्णाङ्क, अचर वर्ण *, पूर्णाङ्क);
पूर्णाङ्क sshkey_load_cert(अचर वर्ण *, संरचना sshkey **);
पूर्णाङ्क sshkey_load_public(अचर वर्ण *, संरचना sshkey **, वर्ण **);
पूर्णाङ्क sshkey_load_private(अचर वर्ण *, अचर वर्ण *, संरचना sshkey **, वर्ण **);
पूर्णाङ्क sshkey_load_private_cert(पूर्णाङ्क, अचर वर्ण *, अचर वर्ण *,
    संरचना sshkey **);
पूर्णाङ्क sshkey_load_private_type(पूर्णाङ्क, अचर वर्ण *, अचर वर्ण *,
    संरचना sshkey **, वर्ण **);
पूर्णाङ्क sshkey_load_private_type_fd(पूर्णाङ्क fd, पूर्णाङ्क type, अचर वर्ण *passphrase,
    संरचना sshkey **keyp, वर्ण **commentp);
पूर्णाङ्क sshkey_perm_ok(पूर्णाङ्क, अचर वर्ण *);
पूर्णाङ्क sshkey_in_file(संरचना sshkey *, अचर वर्ण *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क sshkey_check_revoked(संरचना sshkey *साँचो, अचर वर्ण *revoked_साँचोहरू_file);
पूर्णाङ्क sshkey_advance_past_options(वर्ण **cpp);
पूर्णाङ्क sshkey_save_public(अचर संरचना sshkey *साँचो, अचर वर्ण *path,
    अचर वर्ण *comment);

#endif
