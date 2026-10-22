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

ସଂରଚନା sshbuf;
ସଂରଚନା sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_save_private(ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_cert(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_public(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey **, ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_private(ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey **, ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_private_cert(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ସଂରଚନା sshkey **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_private_type(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ସଂରଚନା sshkey **, ଅକ୍ଷର **);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_load_private_type_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *passphrase,
    ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **commentp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_perm_ok(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅଚଳ ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_in_file(ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_check_revoked(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *revoked_ଚାବିଗୁଡ଼ିକ_file);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_advance_past_options(ଅକ୍ଷର **cpp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshkey_save_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *path,
    ଅଚଳ ଅକ୍ଷର *comment);

#endif
