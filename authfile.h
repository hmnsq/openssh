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

ഘടന sshbuf;
ഘടന sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

പൂർണ്ണസംഖ്യ sshkey_save_private(ഘടന sshkey *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ sshkey_load_cert(സ്ഥിരം അക്ഷരം *, ഘടന sshkey **);
പൂർണ്ണസംഖ്യ sshkey_load_public(സ്ഥിരം അക്ഷരം *, ഘടന sshkey **, അക്ഷരം **);
പൂർണ്ണസംഖ്യ sshkey_load_private(സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന sshkey **, അക്ഷരം **);
പൂർണ്ണസംഖ്യ sshkey_load_private_cert(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    ഘടന sshkey **);
പൂർണ്ണസംഖ്യ sshkey_load_private_type(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    ഘടന sshkey **, അക്ഷരം **);
പൂർണ്ണസംഖ്യ sshkey_load_private_type_fd(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *passphrase,
    ഘടന sshkey **keyp, അക്ഷരം **commentp);
പൂർണ്ണസംഖ്യ sshkey_perm_ok(പൂർണ്ണസംഖ്യ, സ്ഥിരം അക്ഷരം *);
പൂർണ്ണസംഖ്യ sshkey_in_file(ഘടന sshkey *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ sshkey_check_revoked(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *revoked_താക്കോലുകൾ_file);
പൂർണ്ണസംഖ്യ sshkey_advance_past_options(അക്ഷരം **cpp);
പൂർണ്ണസംഖ്യ sshkey_save_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *path,
    സ്ഥിരം അക്ഷരം *comment);

#endif
