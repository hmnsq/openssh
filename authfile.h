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

#నిర్వచితం_కాకపోతే AUTHFILE_H
#నిర్వచించు AUTHFILE_H

నిర్మాణం sshbuf;
నిర్మాణం sshkey;

/* XXX document these */
/* XXX some of these could probably be merged/retired */

పూర్ణాంకం sshkey_save_వ్యక్తిగత(నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం sshkey_ఎక్కించు_cert(స్థిరరాశి అక్షరం *, నిర్మాణం sshkey **);
పూర్ణాంకం sshkey_ఎక్కించు_ప్రజా(స్థిరరాశి అక్షరం *, నిర్మాణం sshkey **, అక్షరం **);
పూర్ణాంకం sshkey_ఎక్కించు_వ్యక్తిగత(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం sshkey **, అక్షరం **);
పూర్ణాంకం sshkey_ఎక్కించు_వ్యక్తిగత_cert(పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    నిర్మాణం sshkey **);
పూర్ణాంకం sshkey_ఎక్కించు_వ్యక్తిగత_type(పూర్ణాంకం, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    నిర్మాణం sshkey **, అక్షరం **);
పూర్ణాంకం sshkey_ఎక్కించు_వ్యక్తిగత_type_fd(పూర్ణాంకం fd, పూర్ణాంకం type, స్థిరరాశి అక్షరం *passphrase,
    నిర్మాణం sshkey **keyp, అక్షరం **commentp);
పూర్ణాంకం sshkey_perm_ok(పూర్ణాంకం, స్థిరరాశి అక్షరం *);
పూర్ణాంకం sshkey_లోపల_file(నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం sshkey_check_revoked(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *revoked_కీలకాలు_file);
పూర్ణాంకం sshkey_advance_past_options(అక్షరం **cpp);
పూర్ణాంకం sshkey_save_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *మార్గం,
    స్థిరరాశి అక్షరం *comment);

#అయితే_ముగింపు
