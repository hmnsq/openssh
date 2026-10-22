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
#define KRL_SECTION_EXPLICIT_KEY	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_KEY_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

sa_nracanaa sshkey;
sa_nracanaa sshbuf;
sa_nracanaa ssh_krl;

sa_nracanaa ssh_krl *ssh_krl_init(void);
void ssh_krl_free(sa_nracanaa ssh_krl *krl);
void ssh_krl_set_version(sa_nracanaa ssh_krl *krl, uint64_t version);
ကိန်းပြည့် ssh_krl_set_comment(sa_nracanaa ssh_krl *krl, const var_na *comment);
ကိန်းပြည့် ssh_krl_revoke_cert_by_serial(sa_nracanaa ssh_krl *krl,
    const sa_nracanaa sshkey *ca_key, uint64_t serial);
ကိန်းပြည့် ssh_krl_revoke_cert_by_serial_range(sa_nracanaa ssh_krl *krl,
    const sa_nracanaa sshkey *ca_key, uint64_t lo, uint64_t hi);
ကိန်းပြည့် ssh_krl_revoke_cert_by_key_id(sa_nracanaa ssh_krl *krl,
    const sa_nracanaa sshkey *ca_key, const var_na *key_id);
ကိန်းပြည့် ssh_krl_revoke_key_explicit(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key);
ကိန်းပြည့် ssh_krl_revoke_key_sha1(sa_nracanaa ssh_krl *krl, const u_char *p, size_t len);
ကိန်းပြည့် ssh_krl_revoke_key_sha256(sa_nracanaa ssh_krl *krl, const u_char *p, size_t len);
ကိန်းပြည့် ssh_krl_revoke_key(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key);
ကိန်းပြည့် ssh_krl_to_blob(sa_nracanaa ssh_krl *krl, sa_nracanaa sshbuf *buf);
ကိန်းပြည့် ssh_krl_from_blob(sa_nracanaa sshbuf *buf, sa_nracanaa ssh_krl **krlp);
ကိန်းပြည့် ssh_krl_check_key(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key);
ကိန်းပြည့် ssh_krl_file_contains_key(const var_na *path, const sa_nracanaa sshkey *key);
ကိန်းပြည့် krl_dump(sa_nracanaa ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

