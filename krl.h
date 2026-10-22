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
#define KRL_SECTION_EXPLICIT_ئاچقۇچ	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_ئاچقۇچ_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

بنية sshkey;
بنية sshbuf;
بنية ssh_krl;

بنية ssh_krl *ssh_krl_init(فراغ);
فراغ ssh_krl_free(بنية ssh_krl *krl);
فراغ ssh_krl_set_version(بنية ssh_krl *krl, uint64_t version);
صحيح ssh_krl_set_comment(بنية ssh_krl *krl, ثابت حرف *comment);
صحيح ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_ئاچقۇچ, uint64_t serial);
صحيح ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_ئاچقۇچ, uint64_t lo, uint64_t hi);
صحيح ssh_krl_revoke_cert_by_ئاچقۇچ_id(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_ئاچقۇچ, ثابت حرف *ئاچقۇچ_id);
صحيح ssh_krl_revoke_ئاچقۇچ_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *ئاچقۇچ);
صحيح ssh_krl_revoke_ئاچقۇچ_sha1(بنية ssh_krl *krl, ثابت u_char *p, size_t len);
صحيح ssh_krl_revoke_ئاچقۇچ_sha256(بنية ssh_krl *krl, ثابت u_char *p, size_t len);
صحيح ssh_krl_revoke_ئاچقۇچ(بنية ssh_krl *krl, ثابت بنية sshkey *ئاچقۇچ);
صحيح ssh_krl_to_blob(بنية ssh_krl *krl, بنية sshbuf *buf);
صحيح ssh_krl_from_blob(بنية sshbuf *buf, بنية ssh_krl **krlp);
صحيح ssh_krl_check_ئاچقۇچ(بنية ssh_krl *krl, ثابت بنية sshkey *ئاچقۇچ);
صحيح ssh_krl_file_contains_ئاچقۇچ(ثابت حرف *path, ثابت بنية sshkey *ئاچقۇچ);
صحيح krl_dump(بنية ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

