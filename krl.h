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

সংরচনা sshkey;
সংরচনা sshbuf;
সংরচনা ssh_krl;

সংরচনা ssh_krl *ssh_krl_init(শূন্য);
শূন্য ssh_krl_free(সংরচনা ssh_krl *krl);
শূন্য ssh_krl_set_version(সংরচনা ssh_krl *krl, uint64_t version);
পূর্ণাঙ্ক ssh_krl_set_comment(সংরচনা ssh_krl *krl, ধ্রুৱ ৱর্ণ *comment);
পূর্ণাঙ্ক ssh_krl_revoke_cert_by_serial(সংরচনা ssh_krl *krl,
    ধ্রুৱ সংরচনা sshkey *ca_চাবি, uint64_t serial);
পূর্ণাঙ্ক ssh_krl_revoke_cert_by_serial_range(সংরচনা ssh_krl *krl,
    ধ্রুৱ সংরচনা sshkey *ca_চাবি, uint64_t lo, uint64_t hi);
পূর্ণাঙ্ক ssh_krl_revoke_cert_by_চাবি_id(সংরচনা ssh_krl *krl,
    ধ্রুৱ সংরচনা sshkey *ca_চাবি, ধ্রুৱ ৱর্ণ *চাবি_id);
পূর্ণাঙ্ক ssh_krl_revoke_চাবি_explicit(সংরচনা ssh_krl *krl, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক ssh_krl_revoke_চাবি_sha1(সংরচনা ssh_krl *krl, ধ্রুৱ u_char *p, size_t len);
পূর্ণাঙ্ক ssh_krl_revoke_চাবি_sha256(সংরচনা ssh_krl *krl, ধ্রুৱ u_char *p, size_t len);
পূর্ণাঙ্ক ssh_krl_revoke_চাবি(সংরচনা ssh_krl *krl, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক ssh_krl_to_blob(সংরচনা ssh_krl *krl, সংরচনা sshbuf *buf);
পূর্ণাঙ্ক ssh_krl_from_blob(সংরচনা sshbuf *buf, সংরচনা ssh_krl **krlp);
পূর্ণাঙ্ক ssh_krl_check_চাবি(সংরচনা ssh_krl *krl, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক ssh_krl_file_contains_চাবি(ধ্রুৱ ৱর্ণ *path, ধ্রুৱ সংরচনা sshkey *চাবি);
পূর্ণাঙ্ক krl_dump(সংরচনা ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

