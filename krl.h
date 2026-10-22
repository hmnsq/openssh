/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: krl.h,v 1.11 2026/03/03 09:57:25 dtucker Exp $ */

#ifndef _KRL_H
#define _KRL_H

/* Functions to manage key revocation lists */

#define KRL_MAGIC		"SSHKRL\n\0"
#define KRL_FORMAT_VERSION	1

/* KRL section types */
#define KRL_SECTION_CERTIFICATES	1
#define KRL_SECTION_EXPLICIT_താക്കോൽ	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_താക്കോൽ_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

ഘടന sshkey;
ഘടന sshbuf;
ഘടന ssh_krl;

ഘടന ssh_krl *ssh_krl_init(ശൂന്യം);
ശൂന്യം ssh_krl_free(ഘടന ssh_krl *krl);
ശൂന്യം ssh_krl_set_version(ഘടന ssh_krl *krl, uint64_t version);
പൂർണ്ണസംഖ്യ ssh_krl_set_comment(ഘടന ssh_krl *krl, സ്ഥിരം അക്ഷരം *comment);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_cert_by_serial(ഘടന ssh_krl *krl,
    സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ, uint64_t serial);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_cert_by_serial_range(ഘടന ssh_krl *krl,
    സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ, uint64_t lo, uint64_t hi);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_cert_by_താക്കോൽ_id(ഘടന ssh_krl *krl,
    സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ, സ്ഥിരം അക്ഷരം *താക്കോൽ_id);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_താക്കോൽ_explicit(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_താക്കോൽ_sha1(ഘടന ssh_krl *krl, സ്ഥിരം u_char *p, size_t len);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_താക്കോൽ_sha256(ഘടന ssh_krl *krl, സ്ഥിരം u_char *p, size_t len);
പൂർണ്ണസംഖ്യ ssh_krl_revoke_താക്കോൽ(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ ssh_krl_to_blob(ഘടന ssh_krl *krl, ഘടന sshbuf *buf);
പൂർണ്ണസംഖ്യ ssh_krl_from_blob(ഘടന sshbuf *buf, ഘടന ssh_krl **krlp);
പൂർണ്ണസംഖ്യ ssh_krl_check_താക്കോൽ(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ ssh_krl_file_contains_താക്കോൽ(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *താക്കോൽ);
പൂർണ്ണസംഖ്യ krl_dump(ഘടന ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

