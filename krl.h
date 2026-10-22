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
#define KRL_SECTION_EXPLICIT_کلید	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_کلید_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

ساختار sshkey;
ساختار sshbuf;
ساختار ssh_krl;

ساختار ssh_krl *ssh_krl_init(تهی);
تهی ssh_krl_free(ساختار ssh_krl *krl);
تهی ssh_krl_set_version(ساختار ssh_krl *krl, uint64_t version);
صحیح ssh_krl_set_comment(ساختار ssh_krl *krl, ثابت نویسه *comment);
صحیح ssh_krl_revoke_cert_by_serial(ساختار ssh_krl *krl,
    ثابت ساختار sshkey *ca_کلید, uint64_t serial);
صحیح ssh_krl_revoke_cert_by_serial_range(ساختار ssh_krl *krl,
    ثابت ساختار sshkey *ca_کلید, uint64_t lo, uint64_t hi);
صحیح ssh_krl_revoke_cert_by_کلید_id(ساختار ssh_krl *krl,
    ثابت ساختار sshkey *ca_کلید, ثابت نویسه *کلید_id);
صحیح ssh_krl_revoke_کلید_explicit(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید);
صحیح ssh_krl_revoke_کلید_sha1(ساختار ssh_krl *krl, ثابت u_char *p, size_t len);
صحیح ssh_krl_revoke_کلید_sha256(ساختار ssh_krl *krl, ثابت u_char *p, size_t len);
صحیح ssh_krl_revoke_کلید(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید);
صحیح ssh_krl_to_blob(ساختار ssh_krl *krl, ساختار sshbuf *buf);
صحیح ssh_krl_from_blob(ساختار sshbuf *buf, ساختار ssh_krl **krlp);
صحیح ssh_krl_check_کلید(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید);
صحیح ssh_krl_file_contains_کلید(ثابت نویسه *path, ثابت ساختار sshkey *کلید);
صحیح krl_dump(ساختار ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

