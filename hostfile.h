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
#నిర్వచితం_కాకపోతే HOSTFILE_H
#నిర్వచించు HOSTFILE_H

రకనిర్వచనం గణన {
	HOST_OK, HOST_NEW, HOST_మారింది, HOST_REVOKED, HOST_దొరికింది
}       Host_స్థితి;

రకనిర్వచనం గణన {
	MRK_ERROR, MRK_NONE, MRK_REVOKE, MRK_CA
}	HostkeyMarker;

నిర్మాణం hostkey_నమోదు {
	అక్షరం *host;
	అక్షరం *file;
	u_long పంక్తి;
	నిర్మాణం sshkey *కీలకం;
	HostkeyMarker marker;
	u_int note; /* caller-specific note/flag */
};
నిర్మాణం hostkeys {
	నిర్మాణం hostkey_నమోదు *entries;
	u_int అంకె_entries;
};

నిర్మాణం hostkeys *init_hostkeys(శూన్య);
శూన్య	 ఎక్కించు_hostkeys(నిర్మాణం hostkeys *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, u_int);
శూన్య	 ఎక్కించు_hostkeys_file(నిర్మాణం hostkeys *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, FILE *, u_int note);
శూన్య	 free_hostkeys(నిర్మాణం hostkeys *);

Host_స్థితి check_కీలకం_లోపల_hostkeys(నిర్మాణం hostkeys *, నిర్మాణం sshkey *,
    స్థిరరాశి నిర్మాణం hostkey_నమోదు **);
పూర్ణాంకం	 lookup_కీలకం_లోపల_hostkeys_by_type(నిర్మాణం hostkeys *, పూర్ణాంకం, పూర్ణాంకం,
    స్థిరరాశి నిర్మాణం hostkey_నమోదు **);
పూర్ణాంకం	 lookup_marker_లోపల_hostkeys(నిర్మాణం hostkeys *, పూర్ణాంకం);

పూర్ణాంకం	 hostfile_read_కీలకం(అక్షరం **, u_int *, నిర్మాణం sshkey *);
పూర్ణాంకం	 కూడు_host_గమ్యం_hostfile(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి నిర్మాణం sshkey *, పూర్ణాంకం);

పూర్ణాంకం	 hostfile_replace_entries(స్థిరరాశి అక్షరం *filename,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, నిర్మాణం sshkey **కీలకాలు, కొలత_t nkeys,
    పూర్ణాంకం store_hash, పూర్ణాంకం quiet, పూర్ణాంకం hash_alg);

#నిర్వచించు HASH_MAGIC	"|1|"
#నిర్వచించు HASH_DELIM	'|'

#నిర్వచించు CA_MARKER	"@cert-authority"
#నిర్వచించు REVOKE_MARKER	"@revoked"

అక్షరం	*host_hash(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, u_int);

/*
 * Iterate through a hostkeys file, optionally parsing keys and matching
 * hostnames. Allows access to the raw keyfile lines to allow
 * streaming edits to the file to take place.
 */
#నిర్వచించు HKF_WANT_సరిపోలిక		(1)	/* return only matching hosts/addrs */
#నిర్వచించు HKF_WANT_PARSE_కీలకం	(1<<1)	/* need key parsed */

#నిర్వచించు HKF_స్థితి_OK		0	/* Line parsed, didn't match host */
#నిర్వచించు HKF_స్థితి_INVALID	1	/* line had parse error */
#నిర్వచించు HKF_స్థితి_COMMENT	2	/* valid line contained no key */
#నిర్వచించు HKF_స్థితి_MATCHED	3	/* hostname or IP matched */

#నిర్వచించు HKF_సరిపోలిక_HOST		(1)	/* hostname matched */
#నిర్వచించు HKF_సరిపోలిక_IP		(1<<1)	/* address matched */
#నిర్వచించు HKF_సరిపోలిక_HOST_HASHED	(1<<2)	/* hostname was hashed */
#నిర్వచించు HKF_సరిపోలిక_IP_HASHED	(1<<3)	/* address was hashed */
/* XXX HKF_MATCH_KEY_TYPE? */

/*
 * The callback function receives this as an argument for each matching 
 * hostkey line. The callback may "steal" the 'key' field by setting it to NULL.
 * If a parse error occurred, then "hosts" and subsequent options may be NULL.
 */
నిర్మాణం hostkey_foreach_పంక్తి {
	స్థిరరాశి అక్షరం *మార్గం; /* Path of file */
	u_long linenum;	/* Line number */
	u_int స్థితి_2;	/* One of HKF_STATUS_* */
	u_int సరిపోలిక;	/* Zero or more of HKF_MATCH_* OR'd together */
	అక్షరం *పంక్తి;	/* Entire key line; mutable by callback */
	పూర్ణాంకం marker;	/* CA/revocation markers; indicated by MRK_* value */
	స్థిరరాశి అక్షరం *hosts; /* Raw hosts text, may be hashed or list multiple */
	స్థిరరాశి అక్షరం *rawkey; /* Text of key and any comment following it */
	పూర్ణాంకం keytype;	/* Type of key; KEY_UNSPEC for invalid/comment lines */
	నిర్మాణం sshkey *కీలకం; /* Key, if parsed ok and HKF_WANT_MATCH_HOST set */
	స్థిరరాశి అక్షరం *comment; /* Any comment following the key */
	u_int note;	/* caller-specified note copied from arguments */
};

/*
 * Callback fires for each line (or matching line if a HKF_WANT_* option
 * is set). The foreach loop will terminate if the callback returns a non-
 * zero exit status.
 */
రకనిర్వచనం పూర్ణాంకం hostkeys_foreach_fn(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *ctx);

/* Iterate over a hostkeys file */
పూర్ణాంకం hostkeys_foreach(స్థిరరాశి అక్షరం *మార్గం,
    hostkeys_foreach_fn *callback, శూన్య *ctx,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, u_int options, u_int note);
పూర్ణాంకం hostkeys_foreach_file(స్థిరరాశి అక్షరం *మార్గం, FILE *f,
    hostkeys_foreach_fn *callback, శూన్య *ctx,
    స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ip, u_int options, u_int note);

శూన్య hostfile_create_user_ssh_dir(స్థిరరాశి అక్షరం *, పూర్ణాంకం);

#అయితే_ముగింపు
