/*
 * Copyright (c) 2000, 2001, 2011, 2013 Corinna Vinschen <vinschen@redhat.com>
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
 *
 * Created: Sat Sep 02 12:17:00 2000 cv
 *
 * This file contains functions for forcing opened file descriptors to
 * binary mode on Windows systems.
 */

#నిర్వచితం_కాకపోతే _BSD_CYGWIN_UTIL_H
#నిర్వచించు _BSD_CYGWIN_UTIL_H

#నిర్వచితమైతే HAVE_CYGWIN

#నిర్వచనం_రద్దు ERROR

/* Avoid including windows headers. */
రకనిర్వచనం శూన్య *HANDLE;
#నిర్వచించు INVALID_HANDLE_విలువ ((HANDLE) -1)
#నిర్వచించు DNLEN 16
#నిర్వచించు UNLEN 256

/* Cygwin functions for which declarations are only available when including
   windows headers, so we have to define them here explicitly. */
బాహ్య HANDLE cygwin_logon_user (స్థిరరాశి నిర్మాణం passwd *, స్థిరరాశి అక్షరం *);
బాహ్య శూన్య cygwin_సమితి_impersonation_token (స్థిరరాశి HANDLE);

#అన్తర్భావ <sys/cygwin.h>
#అన్తర్భావ <io.h>

#నిర్వచించు CYGWIN_SSH_PRIVSEP_USER (cygwin_ssh_privsep_user())
స్థిరరాశి అక్షరం *cygwin_ssh_privsep_user();

పూర్ణాంకం ద్విమాన_open(స్థిరరాశి అక్షరం *, పూర్ణాంకం , ...);
పూర్ణాంకం check_ntsec(స్థిరరాశి అక్షరం *);
అక్షరం **fetch_windows_environment(శూన్య);
శూన్య free_windows_environment(అక్షరం **);
పూర్ణాంకం cygwin_ug_సరిపోలిక_నమూనా_list(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

#నిర్వచితం_కాకపోతే NO_ద్విమాన_OPEN
#నిర్వచించు open ద్విమాన_open
#అయితే_ముగింపు

#అయితే_ముగింపు /* HAVE_CYGWIN */

#అయితే_ముగింపు /* _BSD_CYGWIN_UTIL_H */
