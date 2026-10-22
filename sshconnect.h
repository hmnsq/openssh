/* $OpenBSD: sshconnect.h,v 1.52 2026/08/03 06:47:24 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

నిర్మాణం sshkey;

రకనిర్వచనం నిర్మాణం Sensitive Sensitive;
నిర్మాణం Sensitive {
	నిర్మాణం sshkey	**కీలకాలు;
	పూర్ణాంకం		nkeys;
};

నిర్మాణం ssh_conn_info {
	అక్షరం *conn_hash_hex;
	అక్షరం *shorthost;
	అక్షరం *uidstr;
	అక్షరం *keyalias;
	అక్షరం *thishost;
	అక్షరం *host_arg;
	అక్షరం *portstr;
	అక్షరం *remhost;
	అక్షరం *remuser;
	అక్షరం *homedir;
	అక్షరం *locuser;
	అక్షరం *jmphost;
};

నిర్మాణం addrinfo;
నిర్మాణం ssh;
నిర్మాణం hostkeys;

/* default argument for client percent expansions, minus remote user */
#నిర్వచించు DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు_NOUSER(conn_info) \
	"L", conn_info->shorthost, \
	"i", conn_info->uidstr, \
	"k", conn_info->keyalias, \
	"l", conn_info->thishost, \
	"n", conn_info->host_arg, \
	"p", conn_info->portstr, \
	"d", conn_info->homedir, \
	"h", conn_info->remhost, \
	"u", conn_info->locuser, \
	"j", conn_info->jmphost

/* same plus remote user and hash which has user as a component */
#నిర్వచించు DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_వాదనలు_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

పూర్ణాంకం	 ssh_connect(నిర్మాణం ssh *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
	    నిర్మాణం addrinfo *, నిర్మాణం sockaddr_storage *, u_short,
	    పూర్ణాంకం, పూర్ణాంకం *, పూర్ణాంకం);
శూన్య	 ssh_kill_proxy_command(శూన్య);

శూన్య	 ssh_login(నిర్మాణం ssh *, Sensitive *, స్థిరరాశి అక్షరం *,
    నిర్మాణం sockaddr_storage *, u_short, నిర్మాణం passwd *, పూర్ణాంకం,
    స్థిరరాశి నిర్మాణం ssh_conn_info *);

పూర్ణాంకం	 verify_host_కీలకం(అక్షరం *, నిర్మాణం sockaddr *, నిర్మాణం sshkey *,
    స్థిరరాశి నిర్మాణం ssh_conn_info *);

శూన్య	 get_hostfile_hostname_ipaddr(అక్షరం *, నిర్మాణం sockaddr *, u_short,
    అక్షరం **, అక్షరం **);

శూన్య	 ssh_kex2(నిర్మాణం ssh *ssh, అక్షరం *, నిర్మాణం sockaddr_storage *, u_short,
    స్థిరరాశి నిర్మాణం ssh_conn_info *);

శూన్య	 ssh_userauth2(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    అక్షరం *, Sensitive *);

శూన్య	 pubkey_dump(నిర్మాణం ssh *);

పూర్ణాంకం	 ssh_local_cmd(స్థిరరాశి అక్షరం *);

శూన్య	 maybe_కూడు_కీలకం_గమ్యం_agent(స్థిరరాశి అక్షరం *, నిర్మాణం sshkey *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *);

శూన్య	 ఎక్కించు_hostkeys_command(నిర్మాణం hostkeys *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, స్థిరరాశి నిర్మాణం ssh_conn_info *,
    స్థిరరాశి నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం hostkey_accepted_by_hostkeyalgs(స్థిరరాశి నిర్మాణం sshkey *);

శూన్య ssh_conn_info_free(నిర్మాణం ssh_conn_info *);
నిర్మాణం ssh_conn_info *ssh_conn_info_dup(స్థిరరాశి నిర్మాణం ssh_conn_info *);
