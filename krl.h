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
#define KRL_SECTION_EXPLICIT_চাবি	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_চাবি_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

কাঠামো sshkey;
কাঠামো sshbuf;
কাঠামো ssh_krl;

কাঠামো ssh_krl *ssh_krl_init(শূন্য);
শূন্য ssh_krl_free(কাঠামো ssh_krl *krl);
শূন্য ssh_krl_set_version(কাঠামো ssh_krl *krl, uint64_t version);
পূর্ণসংখ্যা ssh_krl_set_comment(কাঠামো ssh_krl *krl, ধ্রুবক অক্ষর *comment);
পূর্ণসংখ্যা ssh_krl_revoke_cert_by_serial(কাঠামো ssh_krl *krl,
    ধ্রুবক কাঠামো sshkey *ca_চাবি, uint64_t serial);
পূর্ণসংখ্যা ssh_krl_revoke_cert_by_serial_range(কাঠামো ssh_krl *krl,
    ধ্রুবক কাঠামো sshkey *ca_চাবি, uint64_t lo, uint64_t hi);
পূর্ণসংখ্যা ssh_krl_revoke_cert_by_চাবি_id(কাঠামো ssh_krl *krl,
    ধ্রুবক কাঠামো sshkey *ca_চাবি, ধ্রুবক অক্ষর *চাবি_id);
পূর্ণসংখ্যা ssh_krl_revoke_চাবি_explicit(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা ssh_krl_revoke_চাবি_sha1(কাঠামো ssh_krl *krl, ধ্রুবক u_char *p, আকার_t len);
পূর্ণসংখ্যা ssh_krl_revoke_চাবি_sha256(কাঠামো ssh_krl *krl, ধ্রুবক u_char *p, আকার_t len);
পূর্ণসংখ্যা ssh_krl_revoke_চাবি(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা ssh_krl_to_blob(কাঠামো ssh_krl *krl, কাঠামো sshbuf *buf);
পূর্ণসংখ্যা ssh_krl_from_blob(কাঠামো sshbuf *buf, কাঠামো ssh_krl **krlp);
পূর্ণসংখ্যা ssh_krl_check_চাবি(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা ssh_krl_file_contains_চাবি(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *চাবি);
পূর্ণসংখ্যা krl_dump(কাঠামো ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

