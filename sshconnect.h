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

কাঠামো sshkey;

প্রকারলেখ কাঠামো Sensitive Sensitive;
কাঠামো Sensitive {
	কাঠামো sshkey	**চাবিগুলি;
	পূর্ণসংখ্যা		nkeys;
};

কাঠামো ssh_conn_info {
	অক্ষর *conn_hash_hex;
	অক্ষর *shorthost;
	অক্ষর *uidstr;
	অক্ষর *keyalias;
	অক্ষর *thishost;
	অক্ষর *host_arg;
	অক্ষর *portstr;
	অক্ষর *remhost;
	অক্ষর *remuser;
	অক্ষর *homedir;
	অক্ষর *locuser;
	অক্ষর *jmphost;
};

কাঠামো addrinfo;
কাঠামো ssh;
কাঠামো hostkeys;

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

পূর্ণসংখ্যা	 ssh_connect(কাঠামো ssh *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
	    কাঠামো addrinfo *, কাঠামো sockaddr_storage *, u_short,
	    পূর্ণসংখ্যা, পূর্ণসংখ্যা *, পূর্ণসংখ্যা);
শূন্য	 ssh_kill_proxy_command(শূন্য);

শূন্য	 ssh_login(কাঠামো ssh *, Sensitive *, ধ্রুবক অক্ষর *,
    কাঠামো sockaddr_storage *, u_short, কাঠামো passwd *, পূর্ণসংখ্যা,
    ধ্রুবক কাঠামো ssh_conn_info *);

পূর্ণসংখ্যা	 verify_host_চাবি(অক্ষর *, কাঠামো sockaddr *, কাঠামো sshkey *,
    ধ্রুবক কাঠামো ssh_conn_info *);

শূন্য	 get_hostfile_hostname_ipaddr(অক্ষর *, কাঠামো sockaddr *, u_short,
    অক্ষর **, অক্ষর **);

শূন্য	 ssh_kex2(কাঠামো ssh *ssh, অক্ষর *, কাঠামো sockaddr_storage *, u_short,
    ধ্রুবক কাঠামো ssh_conn_info *);

শূন্য	 ssh_userauth2(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    অক্ষর *, Sensitive *);

শূন্য	 pubkey_dump(কাঠামো ssh *);

পূর্ণসংখ্যা	 ssh_local_cmd(ধ্রুবক অক্ষর *);

শূন্য	 maybe_add_চাবি_to_agent(ধ্রুবক অক্ষর *, কাঠামো sshkey *,
    ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *);

শূন্য	 load_hostkeys_command(কাঠামো hostkeys *, ধ্রুবক অক্ষর *,
    ধ্রুবক অক্ষর *, ধ্রুবক কাঠামো ssh_conn_info *,
    ধ্রুবক কাঠামো sshkey *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা hostkey_accepted_by_hostkeyalgs(ধ্রুবক কাঠামো sshkey *);

শূন্য ssh_conn_info_free(কাঠামো ssh_conn_info *);
কাঠামো ssh_conn_info *ssh_conn_info_dup(ধ্রুবক কাঠামো ssh_conn_info *);
