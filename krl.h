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

#اگر_غیر_تعریف_شدہ _KRL_H
#تعریف_کرو _KRL_H

/* Functions to manage key revocation lists */

#تعریف_کرو KRL_MAGIC		"SSHKRL\n\0"
#تعریف_کرو KRL_FORMAT_نسخہ	1

/* KRL section types */
#تعریف_کرو KRL_SECTION_CERTIFICATES	1
#تعریف_کرو KRL_SECTION_EXPLICIT_کلید	2
#تعریف_کرو KRL_SECTION_FINGERPRINT_SHA1	3
#تعریف_کرو KRL_SECTION_SIGNATURE		4
#تعریف_کرو KRL_SECTION_FINGERPRINT_SHA256	5
#تعریف_کرو KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#تعریف_کرو KRL_SECTION_CERT_SERIAL_LIST	0x20
#تعریف_کرو KRL_SECTION_CERT_SERIAL_RANGE	0x21
#تعریف_کرو KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#تعریف_کرو KRL_SECTION_CERT_کلید_ID		0x23
#تعریف_کرو KRL_SECTION_CERT_EXTENSION	0x39

ساخت sshkey;
ساخت sshbuf;
ساخت ssh_krl;

ساخت ssh_krl *ssh_krl_init(خالی);
خالی ssh_krl_free(ساخت ssh_krl *krl);
خالی ssh_krl_سیٹ_نسخہ(ساخت ssh_krl *krl, uint64_t نسخہ);
صحیح ssh_krl_سیٹ_comment(ساخت ssh_krl *krl, ثابت حرف *comment);
صحیح ssh_krl_revoke_cert_by_serial(ساخت ssh_krl *krl,
    ثابت ساخت sshkey *ca_کلید, uint64_t serial);
صحیح ssh_krl_revoke_cert_by_serial_range(ساخت ssh_krl *krl,
    ثابت ساخت sshkey *ca_کلید, uint64_t lo, uint64_t hi);
صحیح ssh_krl_revoke_cert_by_کلید_id(ساخت ssh_krl *krl,
    ثابت ساخت sshkey *ca_کلید, ثابت حرف *کلید_id);
صحیح ssh_krl_revoke_کلید_explicit(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید);
صحیح ssh_krl_revoke_کلید_sha1(ساخت ssh_krl *krl, ثابت u_char *p, سائز_t len);
صحیح ssh_krl_revoke_کلید_sha256(ساخت ssh_krl *krl, ثابت u_char *p, سائز_t len);
صحیح ssh_krl_revoke_کلید(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید);
صحیح ssh_krl_مقصد_blob(ساخت ssh_krl *krl, ساخت sshbuf *buf);
صحیح ssh_krl_from_blob(ساخت sshbuf *buf, ساخت ssh_krl **krlp);
صحیح ssh_krl_check_کلید(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید);
صحیح ssh_krl_file_شامل_ہے_کلید(ثابت حرف *راستہ, ثابت ساخت sshkey *کلید);
صحیح krl_dump(ساخت ssh_krl *krl, FILE *f);

#اگر_ختم /* _KRL_H */

