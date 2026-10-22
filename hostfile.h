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
#اگر_غیر_تعریف_شدہ HOSTFILE_H
#تعریف_کرو HOSTFILE_H

قسمتعریف شمار {
	HOST_OK, HOST_NEW, HOST_بدلا, HOST_REVOKED, HOST_ملا
}       Host_حالت;

قسمتعریف شمار {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

ساخت hostkey_اندراج {
	حرف *host;
	حرف *file;
	u_long سطر;
	ساخت sshkey *کلید;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
ساخت hostkeys {
	ساخت hostkey_اندراج *entries;
	u_int عدد_entries;
};

ساخت hostkeys *init_hostkeys(خالی);
خالی	 بھرو_hostkeys(ساخت hostkeys *, ثابت حرف *,
    ثابت حرف *, u_int);
خالی	 بھرو_hostkeys_file(ساخت hostkeys *, ثابت حرف *,
    ثابت حرف *, FILE *, u_int note);
خالی	 free_hostkeys(ساخت hostkeys *);

Host_حالت check_کلید_اندر_hostkeys(ساخت hostkeys *, ساخت sshkey *,
    ثابت ساخت hostkey_اندراج **);
صحیح	 lookup_کلید_اندر_hostkeys_by_type(ساخت hostkeys *, صحیح, صحیح,
    ثابت ساخت hostkey_اندراج **);
صحیح	 lookup_marker_اندر_hostkeys(ساخت hostkeys *, صحیح);

صحیح	 hostfile_read_کلید(حرف **, u_int *, ساخت sshkey *);
صحیح	 جوڑو_host_مقصد_hostfile(ثابت حرف *, ثابت حرف *,
    ثابت ساخت sshkey *, صحیح);

صحیح	 hostfile_replace_entries(ثابت حرف *filename,
    ثابت حرف *host, ثابت حرف *ip, ساخت sshkey **کلیدیں, سائز_t nkeys,
    صحیح store_hash, صحیح quiet, صحیح hash_alg);

#تعریف_کرو HASH_MAGIC	"|1|"
#تعریف_کرو HASH_DELIM	'|'

#تعریف_کرو CA_MARKER	"@cert-authority"
#تعریف_کرو REVOKE_MARKER	"@revoked"

حرف	*host_hash(ثابت حرف *, ثابت حرف *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#تعریف_کرو HKF_WANT_مطابقت		(1)	/* return only matching hosts/addrs */
#تعریف_کرو HKF_WANT_PARSE_کلید	(1<<1)	/* need key parsed */

#تعریف_کرو HKF_حالت_OK		0	/* Line parsed, didn't match host */
#تعریف_کرو HKF_حالت_INVALID	1	/* line had parse error */
#تعریف_کرو HKF_حالت_COMMENT	2	/* valid line contained no key */
#تعریف_کرو HKF_حالت_MATCHED	3	/* hostname or IP matched */

#تعریف_کرو HKF_مطابقت_HOST		(1)	/* hostname matched */
#تعریف_کرو HKF_مطابقت_IP		(1<<1)	/* address matched */
#تعریف_کرو HKF_مطابقت_HOST_HASHED	(1<<2)	/* hostname was hashed */
#تعریف_کرو HKF_مطابقت_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
ساخت hostkey_foreach_سطر {
	ثابت حرف *راستہ; /* Path of file */
	u_long linenum;	/* Line number */
	u_int حالت_2;	/* One of HKF_STATUS_* */
	u_int مطابقت;	/* Zero or more of HKF_MATCH_* OR'd together */
	حرف *سطر;	/* Entire key line; mutable by callback */
	صحیح marker;	/* CA/revocation markers; indicated by MRK_* value */
	ثابت حرف *hosts; /* Raw hosts text, may be hashed or list multiple */
	ثابت حرف *rawkey; /* Text of key and any comment following it */
	صحیح keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	ساخت sshkey *کلید; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	ثابت حرف *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
قسمتعریف صحیح hostkeys_foreach_fn(ساخت hostkey_foreach_سطر *l, خالی *ctx);

/* Iterate over a hostkeys file */
صحیح hostkeys_foreach(ثابت حرف *راستہ,
    hostkeys_foreach_fn *callback, خالی *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);
صحیح hostkeys_foreach_file(ثابت حرف *راستہ, FILE *f,
    hostkeys_foreach_fn *callback, خالی *ctx,
    ثابت حرف *host, ثابت حرف *ip, u_int options, u_int note);

خالی hostfile_create_user_ssh_dir(ثابت حرف *, صحیح);

#اگر_ختم
