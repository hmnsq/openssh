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

संरचना sshkey;

प्रकारव्याख्या संरचना Sensitive Sensitive;
संरचना Sensitive {
	संरचना sshkey	**किल्ल्या;
	पूर्णांक		nkeys;
};

संरचना ssh_conn_info {
	अक्षर *conn_hash_hex;
	अक्षर *shorthost;
	अक्षर *uidstr;
	अक्षर *keyalias;
	अक्षर *thishost;
	अक्षर *host_arg;
	अक्षर *portstr;
	अक्षर *remhost;
	अक्षर *remuser;
	अक्षर *homedir;
	अक्षर *locuser;
	अक्षर *jmphost;
};

संरचना addrinfo;
संरचना ssh;
संरचना hostkeys;

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

पूर्णांक	 ssh_connect(संरचना ssh *, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
	    संरचना addrinfo *, संरचना sockaddr_storage *, u_short,
	    पूर्णांक, पूर्णांक *, पूर्णांक);
शून्य	 ssh_kill_proxy_command(शून्य);

शून्य	 ssh_login(संरचना ssh *, Sensitive *, स्थिरांक अक्षर *,
    संरचना sockaddr_storage *, u_short, संरचना passwd *, पूर्णांक,
    स्थिरांक संरचना ssh_conn_info *);

पूर्णांक	 verify_host_किल्ली(अक्षर *, संरचना sockaddr *, संरचना sshkey *,
    स्थिरांक संरचना ssh_conn_info *);

शून्य	 get_hostfile_hostname_ipaddr(अक्षर *, संरचना sockaddr *, u_short,
    अक्षर **, अक्षर **);

शून्य	 ssh_kex2(संरचना ssh *ssh, अक्षर *, संरचना sockaddr_storage *, u_short,
    स्थिरांक संरचना ssh_conn_info *);

शून्य	 ssh_userauth2(संरचना ssh *ssh, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    अक्षर *, Sensitive *);

शून्य	 pubkey_dump(संरचना ssh *);

पूर्णांक	 ssh_local_cmd(स्थिरांक अक्षर *);

शून्य	 maybe_add_किल्ली_to_agent(स्थिरांक अक्षर *, संरचना sshkey *,
    स्थिरांक अक्षर *, स्थिरांक अक्षर *);

शून्य	 load_hostkeys_command(संरचना hostkeys *, स्थिरांक अक्षर *,
    स्थिरांक अक्षर *, स्थिरांक संरचना ssh_conn_info *,
    स्थिरांक संरचना sshkey *, स्थिरांक अक्षर *);

पूर्णांक hostkey_accepted_by_hostkeyalgs(स्थिरांक संरचना sshkey *);

शून्य ssh_conn_info_free(संरचना ssh_conn_info *);
संरचना ssh_conn_info *ssh_conn_info_dup(स्थिरांक संरचना ssh_conn_info *);
