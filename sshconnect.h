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

ସଂରଚନା sshkey;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା Sensitive Sensitive;
ସଂରଚନା Sensitive {
	ସଂରଚନା sshkey	**ଚାବିଗୁଡ଼ିକ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		nkeys;
};

ସଂରଚନା ssh_conn_info {
	ଅକ୍ଷର *conn_hash_hex;
	ଅକ୍ଷର *shorthost;
	ଅକ୍ଷର *uidstr;
	ଅକ୍ଷର *keyalias;
	ଅକ୍ଷର *thishost;
	ଅକ୍ଷର *host_arg;
	ଅକ୍ଷର *portstr;
	ଅକ୍ଷର *remhost;
	ଅକ୍ଷର *remuser;
	ଅକ୍ଷର *homedir;
	ଅକ୍ଷର *locuser;
	ଅକ୍ଷର *jmphost;
};

ସଂରଚନା addrinfo;
ସଂରଚନା ssh;
ସଂରଚନା hostkeys;

/* default argument for client percent expansions, minus remote user */
#define DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info) \
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
#define DEFAULT_CLIENT_PERCENT_EXPAND_ARGS(conn_info) \
	DEFAULT_CLIENT_PERCENT_EXPAND_ARGS_NOUSER(conn_info), \
	"C", conn_info->conn_hash_hex, \
	"r", conn_info->remuser

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_connect(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
	    ସଂରଚନା addrinfo *, ସଂରଚନା sockaddr_storage *, u_short,
	    ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 ssh_kill_proxy_command(ଶୂନ୍ୟ);

ଶୂନ୍ୟ	 ssh_login(ସଂରଚନା ssh *, Sensitive *, ଅଚଳ ଅକ୍ଷର *,
    ସଂରଚନା sockaddr_storage *, u_short, ସଂରଚନା passwd *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ଅଚଳ ସଂରଚନା ssh_conn_info *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 verify_host_ଚାବି(ଅକ୍ଷର *, ସଂରଚନା sockaddr *, ସଂରଚନା sshkey *,
    ଅଚଳ ସଂରଚନା ssh_conn_info *);

ଶୂନ୍ୟ	 get_hostfile_hostname_ipaddr(ଅକ୍ଷର *, ସଂରଚନା sockaddr *, u_short,
    ଅକ୍ଷର **, ଅକ୍ଷର **);

ଶୂନ୍ୟ	 ssh_kex2(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *, ସଂରଚନା sockaddr_storage *, u_short,
    ଅଚଳ ସଂରଚନା ssh_conn_info *);

ଶୂନ୍ୟ	 ssh_userauth2(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    ଅକ୍ଷର *, Sensitive *);

ଶୂନ୍ୟ	 pubkey_dump(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_local_cmd(ଅଚଳ ଅକ୍ଷର *);

ଶୂନ୍ୟ	 maybe_add_ଚାବି_to_agent(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshkey *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *);

ଶୂନ୍ୟ	 load_hostkeys_command(ସଂରଚନା hostkeys *, ଅଚଳ ଅକ୍ଷର *,
    ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ସଂରଚନା ssh_conn_info *,
    ଅଚଳ ସଂରଚନା sshkey *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା hostkey_accepted_by_hostkeyalgs(ଅଚଳ ସଂରଚନା sshkey *);

ଶୂନ୍ୟ ssh_conn_info_free(ସଂରଚନା ssh_conn_info *);
ସଂରଚନା ssh_conn_info *ssh_conn_info_dup(ଅଚଳ ସଂରଚନା ssh_conn_info *);
