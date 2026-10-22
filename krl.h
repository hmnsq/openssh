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

#اگر_تعریف_نشده _KRL_H
#تعریف_کن _KRL_H

/* Functions to manage key revocation lists */

#تعریف_کن KRL_MAGIC		"SSHKRL\n\0"
#تعریف_کن KRL_FORMAT_نسخه	1

/* KRL section types */
#تعریف_کن KRL_SECTION_CERTIFICATES	1
#تعریف_کن KRL_SECTION_EXPLICIT_کلید	2
#تعریف_کن KRL_SECTION_FINGERPRINT_SHA1	3
#تعریف_کن KRL_SECTION_SIGNATURE		4
#تعریف_کن KRL_SECTION_FINGERPRINT_SHA256	5
#تعریف_کن KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#تعریف_کن KRL_SECTION_CERT_SERIAL_LIST	0x20
#تعریف_کن KRL_SECTION_CERT_SERIAL_RANGE	0x21
#تعریف_کن KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#تعریف_کن KRL_SECTION_CERT_کلید_ID		0x23
#تعریف_کن KRL_SECTION_CERT_EXTENSION	0x39

بنية sshkey;
بنية sshbuf;
بنية ssh_krl;

بنية ssh_krl *ssh_krl_init(فراغ);
فراغ ssh_krl_free(بنية ssh_krl *krl);
فراغ ssh_krl_مجموعه_نسخه(بنية ssh_krl *krl, uint64_t نسخه);
صحيح ssh_krl_مجموعه_comment(بنية ssh_krl *krl, ثابت حرف *comment);
صحيح ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلید, uint64_t serial);
صحيح ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلید, uint64_t lo, uint64_t hi);
صحيح ssh_krl_revoke_cert_by_کلید_id(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلید, ثابت حرف *کلید_id);
صحيح ssh_krl_revoke_کلید_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *کلید);
صحيح ssh_krl_revoke_کلید_sha1(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len);
صحيح ssh_krl_revoke_کلید_sha256(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len);
صحيح ssh_krl_revoke_کلید(بنية ssh_krl *krl, ثابت بنية sshkey *کلید);
صحيح ssh_krl_مقصد_blob(بنية ssh_krl *krl, بنية sshbuf *buf);
صحيح ssh_krl_from_blob(بنية sshbuf *buf, بنية ssh_krl **krlp);
صحيح ssh_krl_check_کلید(بنية ssh_krl *krl, ثابت بنية sshkey *کلید);
صحيح ssh_krl_file_شامل_است_کلید(ثابت حرف *مسیر, ثابت بنية sshkey *کلید);
صحيح krl_dump(بنية ssh_krl *krl, FILE *f);

#پایان_اگر /* _KRL_H */

