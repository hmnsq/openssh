/* $OpenBSD: hostfile.h,v 1.29 2021/01/26 00:51:30 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HOSTFILE_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HOSTFILE_H

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	HOST_OK, HOST_NEW, HOST_ਬਦਲਿਆ, HOST_REVOKED, HOST_ਮਿਲਿਆ
}       Host_ਸਥਿਤੀ;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ਬਣਤਰ hostkey_ਇੰਦਰਾਜ {
	ਅੱਖਰ *host;
	ਅੱਖਰ *file;
	u_long ਸਤਰ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ਬਣਤਰ hostkeys {
	ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *entries;
	u_int ਅੰਕ_entries;
};

ਬਣਤਰ hostkeys *init_hostkeys(ਖਾਲੀ);
ਖਾਲੀ	 ਲੱਦੋ_hostkeys(ਬਣਤਰ hostkeys *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, u_int);
ਖਾਲੀ	 ਲੱਦੋ_hostkeys_file(ਬਣਤਰ hostkeys *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਅੱਖਰ *, FILE *, u_int note);
ਖਾਲੀ	 free_hostkeys(ਬਣਤਰ hostkeys *);

Host_ਸਥਿਤੀ check_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys(ਬਣਤਰ hostkeys *, ਬਣਤਰ sshkey *,
    ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ **);
ਪੂਰਨ	 lookup_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys_by_type(ਬਣਤਰ hostkeys *, ਪੂਰਨ, ਪੂਰਨ,
    ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ **);
ਪੂਰਨ	 lookup_marker_ਵਿੱਚ_hostkeys(ਬਣਤਰ hostkeys *, ਪੂਰਨ);

ਪੂਰਨ	 hostfile_read_ਕੁੰਜੀ(ਅੱਖਰ **, u_int *, ਬਣਤਰ sshkey *);
ਪੂਰਨ	 ਜੋੜੋ_host_ਮੰਜ਼ਿਲ_hostfile(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    ਅਚਲ ਬਣਤਰ sshkey *, ਪੂਰਨ);

ਪੂਰਨ	 hostfile_replace_entries(ਅਚਲ ਅੱਖਰ *filename,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, ਬਣਤਰ sshkey **ਕੁੰਜੀਆਂ, ਮਾਪ_t nkeys,
    ਪੂਰਨ store_hash, ਪੂਰਨ quiet, ਪੂਰਨ hash_alg);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HASH_MAGIC	"|1|"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HASH_DELIM	'|'

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CA_MARKER	"@cert-authority"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REVOKE_MARKER	"@revoked"

ਅੱਖਰ	*host_hash(ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_WANT_ਮੇਲ		(1)	/* return only matching hosts/addrs */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_WANT_PARSE_ਕੁੰਜੀ	(1<<1)	/* need key parsed */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਸਥਿਤੀ_OK		0	/* Line parsed, didn't match host */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਸਥਿਤੀ_INVALID	1	/* line had parse error */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਸਥਿਤੀ_COMMENT	2	/* valid line contained no key */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਸਥਿਤੀ_MATCHED	3	/* hostname or IP matched */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਮੇਲ_HOST		(1)	/* hostname matched */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਮੇਲ_IP		(1<<1)	/* address matched */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਮੇਲ_HOST_HASHED	(1<<2)	/* hostname was hashed */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HKF_ਮੇਲ_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
ਬਣਤਰ hostkey_foreach_ਸਤਰ {
	ਅਚਲ ਅੱਖਰ *ਰਸਤਾ; /* Path of file */
	u_long linenum;	/* Line number */
	u_int ਸਥਿਤੀ;	/* One of HKF_STATUS_* */
	u_int ਮੇਲ;	/* Zero or more of HKF_MATCH_* OR'd together */
	ਅੱਖਰ *ਸਤਰ;	/* Entire key line; mutable by callback */
	ਪੂਰਨ marker;	/* CA/revocation markers; indicated by MRK_* value */
	ਅਚਲ ਅੱਖਰ *hosts; /* Raw hosts text, may be hashed or list multiple */
	ਅਚਲ ਅੱਖਰ *rawkey; /* Text of key and any comment following it */
	ਪੂਰਨ keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ਬਣਤਰ sshkey *ਕੁੰਜੀ; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ਅਚਲ ਅੱਖਰ *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ hostkeys_foreach_fn(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *ctx);

/* Iterate over a hostkeys file */
ਪੂਰਨ hostkeys_foreach(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    hostkeys_foreach_fn *callback, ਖਾਲੀ *ctx,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, u_int options, u_int note);
ਪੂਰਨ hostkeys_foreach_file(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, FILE *f,
    hostkeys_foreach_fn *callback, ਖਾਲੀ *ctx,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ip, u_int options, u_int note);

ਖਾਲੀ hostfile_create_user_ssh_dir(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ);

#ਜੇ_ਅੰਤ
