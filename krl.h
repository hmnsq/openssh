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

#నిర్వచితం_కాకపోతే _KRL_H
#నిర్వచించు _KRL_H

/* Functions to manage key revocation lists */

#నిర్వచించు KRL_MAGIC		"SSHKRL\n\0"
#నిర్వచించు KRL_FORMAT_సంస్కరణ	1

/* KRL section types */
#నిర్వచించు KRL_SECTION_CERTIFICATES	1
#నిర్వచించు KRL_SECTION_EXPLICIT_కీలకం	2
#నిర్వచించు KRL_SECTION_FINGERPRINT_SHA1	3
#నిర్వచించు KRL_SECTION_SIGNATURE		4
#నిర్వచించు KRL_SECTION_FINGERPRINT_SHA256	5
#నిర్వచించు KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#నిర్వచించు KRL_SECTION_CERT_SERIAL_LIST	0x20
#నిర్వచించు KRL_SECTION_CERT_SERIAL_RANGE	0x21
#నిర్వచించు KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#నిర్వచించు KRL_SECTION_CERT_కీలకం_ID		0x23
#నిర్వచించు KRL_SECTION_CERT_EXTENSION	0x39

నిర్మాణం sshkey;
నిర్మాణం sshbuf;
నిర్మాణం ssh_krl;

నిర్మాణం ssh_krl *ssh_krl_init(శూన్య);
శూన్య ssh_krl_free(నిర్మాణం ssh_krl *krl);
శూన్య ssh_krl_సమితి_సంస్కరణ(నిర్మాణం ssh_krl *krl, uint64_t సంస్కరణ);
పూర్ణాంకం ssh_krl_సమితి_comment(నిర్మాణం ssh_krl *krl, స్థిరరాశి అక్షరం *comment);
పూర్ణాంకం ssh_krl_revoke_cert_by_serial(నిర్మాణం ssh_krl *krl,
    స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం, uint64_t serial);
పూర్ణాంకం ssh_krl_revoke_cert_by_serial_range(నిర్మాణం ssh_krl *krl,
    స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం, uint64_t lo, uint64_t hi);
పూర్ణాంకం ssh_krl_revoke_cert_by_కీలకం_id(నిర్మాణం ssh_krl *krl,
    స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం, స్థిరరాశి అక్షరం *కీలకం_id);
పూర్ణాంకం ssh_krl_revoke_కీలకం_explicit(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం ssh_krl_revoke_కీలకం_sha1(నిర్మాణం ssh_krl *krl, స్థిరరాశి u_char *p, కొలత_t len);
పూర్ణాంకం ssh_krl_revoke_కీలకం_sha256(నిర్మాణం ssh_krl *krl, స్థిరరాశి u_char *p, కొలత_t len);
పూర్ణాంకం ssh_krl_revoke_కీలకం(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం ssh_krl_గమ్యం_blob(నిర్మాణం ssh_krl *krl, నిర్మాణం sshbuf *buf);
పూర్ణాంకం ssh_krl_from_blob(నిర్మాణం sshbuf *buf, నిర్మాణం ssh_krl **krlp);
పూర్ణాంకం ssh_krl_check_కీలకం(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం ssh_krl_file_కలిగియుంది_కీలకం(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *కీలకం);
పూర్ణాంకం krl_dump(నిర్మాణం ssh_krl *krl, FILE *f);

#అయితే_ముగింపు /* _KRL_H */

