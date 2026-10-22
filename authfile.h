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

સંરચના sshbuf;
સંરચના sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

પૂર્ણાંક sshkey_save_private(સંરચના sshkey *, અચલ અક્ષર *,
    અચલ અક્ષર *, અચલ અક્ષર *, પૂર્ણાંક, અચલ અક્ષર *, પૂર્ણાંક);
પૂર્ણાંક sshkey_load_cert(અચલ અક્ષર *, સંરચના sshkey **);
પૂર્ણાંક sshkey_load_public(અચલ અક્ષર *, સંરચના sshkey **, અક્ષર **);
પૂર્ણાંક sshkey_load_private(અચલ અક્ષર *, અચલ અક્ષર *, સંરચના sshkey **, અક્ષર **);
પૂર્ણાંક sshkey_load_private_cert(પૂર્ણાંક, અચલ અક્ષર *, અચલ અક્ષર *,
    સંરચના sshkey **);
પૂર્ણાંક sshkey_load_private_type(પૂર્ણાંક, અચલ અક્ષર *, અચલ અક્ષર *,
    સંરચના sshkey **, અક્ષર **);
પૂર્ણાંક sshkey_load_private_type_fd(પૂર્ણાંક fd, પૂર્ણાંક type, અચલ અક્ષર *passphrase,
    સંરચના sshkey **keyp, અક્ષર **commentp);
પૂર્ણાંક sshkey_perm_ok(પૂર્ણાંક, અચલ અક્ષર *);
પૂર્ણાંક sshkey_in_file(સંરચના sshkey *, અચલ અક્ષર *, પૂર્ણાંક, પૂર્ણાંક);
પૂર્ણાંક sshkey_check_revoked(સંરચના sshkey *ચાવી, અચલ અક્ષર *revoked_ચાવીઓ_file);
પૂર્ણાંક sshkey_advance_past_options(અક્ષર **cpp);
પૂર્ણાંક sshkey_save_public(અચલ સંરચના sshkey *ચાવી, અચલ અક્ષર *path,
    અચલ અક્ષર *comment);

#endif
