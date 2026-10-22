// libfuzzer driver for key exchange fuzzing.


#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య "C" {

#అన్తర్భావ "includes.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "log.h"

#అన్తర్భావ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

స్థిర పూర్ణాంకం prepare_కీలకం(నిర్మాణం shared_state *st, పూర్ణాంకం keytype, పూర్ణాంకం బిట్లు);

నిర్మాణం shared_state {
	కొలత_t nkeys;
	నిర్మాణం sshkey **privkeys, **pubkeys;
};

నిర్మాణం test_state {
	నిర్మాణం sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	నిర్మాణం sshbuf *జ్యా, *లోపలికి; /* input; setup per-test in do_kex_with_key */
	నిర్మాణం sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
నిర్మాణం kex_overrides {
	స్థిరరాశి అక్షరం *cipher;
	స్థిరరాశి అక్షరం *mac;
	స్థిరరాశి అక్షరం *comp;
};

స్థిర పూర్ణాంకం
do_send_and_receive(నిర్మాణం ssh *from, నిర్మాణం ssh *గమ్యం,
    నిర్మాణం sshbuf *store, పూర్ణాంకం clobber, కొలత_t *n)
{
	u_char type;
	కొలత_t len;
	స్థిరరాశి u_char *buf;
	పూర్ణాంకం r;

	కొరకు (*n = 0;; (*n)++) {
		ఒకవేళ ((r = ssh_packet_తదుపరి(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			తిరిగి r;
		}
		ఒకవేళ (type != 0)
			తిరిగి 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ఒకవేళ (len == 0)
			తిరిగి 0;
		ఒకవేళ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			తిరిగి r;
		}
		ఒకవేళ (store != ఖాళీ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			తిరిగి r;
		}
		ఒకవేళ (!clobber && (r = ssh_ఆదానం_append(గమ్యం, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			తిరిగి r;
		}
	}
}

స్థిర పూర్ణాంకం
నిరంతరం_kex(నిర్మాణం test_state *ts, నిర్మాణం ssh *client, నిర్మాణం ssh *server)
{
	పూర్ణాంకం r = 0;
	కొలత_t cn, sn;

	/* If fuzzing, replace server/client input */
	ఒకవేళ (ts->జ్యా != ఖాళీ) {
		ఒకవేళ ((r = ssh_ఆదానం_append(server, sshbuf_ptr(ts->జ్యా),
		    sshbuf_len(ts->జ్యా))) != 0) {
			error_fr(r, "ssh_input_append");
			తిరిగి r;
		}
		sshbuf_reset(ts->జ్యా);
	}
	ఒకవేళ (ts->లోపలికి != ఖాళీ) {
		ఒకవేళ ((r = ssh_ఆదానం_append(client, sshbuf_ptr(ts->లోపలికి),
		    sshbuf_len(ts->లోపలికి))) != 0) {
			error_fr(r, "ssh_input_append");
			తిరిగి r;
		}
		sshbuf_reset(ts->లోపలికి);
	}
	అయితే (!server->kex->పూర్తి || !client->kex->పూర్తి) {
		cn = sn = 0;
		debug_f("S:");
		ఒకవేళ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->లోపలికి != ఖాళీ, &sn)) != 0) {
			debug_fr(r, "S->C");
			ఆపు;
		}
		debug_f("C:");
		ఒకవేళ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->జ్యా != ఖాళీ, &cn)) != 0) {
			debug_fr(r, "C->S");
			ఆపు;
		}
		ఒకవేళ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ఆపు;
		}
	}
	debug_fr(r, "done");
	తిరిగి r;
}

స్థిర శూన్య
store_కీలకం(నిర్మాణం shared_state *st, నిర్మాణం sshkey *pubkey,
    నిర్మాణం sshkey *privkey)
{
	ఒకవేళ (st == ఖాళీ || pubkey->type < 0 || pubkey->type > గరిష్ఠ_పూర్ణాంకం ||
	    privkey->type != pubkey->type ||
	    ((కొలత_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ఖాళీ))
		abort();
	ఒకవేళ ((కొలత_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (నిర్మాణం sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, పరిమాణం(*st->pubkeys));
		st->privkeys = (నిర్మాణం sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, పరిమాణం(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

స్థిర పూర్ణాంకం
prepare_కీలకాలు(నిర్మాణం shared_state *st)
{
	ఒకవేళ (prepare_కీలకం(st, కీలకం_RSA, 2048) != 0 ||
	    prepare_కీలకం(st, కీలకం_ECDSA, 256) != 0 ||
	    prepare_కీలకం(st, కీలకం_ED25519, 256) != 0) {
		error_f("key prepare failed");
		తిరిగి -1;
	}
	తిరిగి 0;
}

స్థిర నిర్మాణం sshkey *
get_pubkey(నిర్మాణం shared_state *st, పూర్ణాంకం keytype)
{
	ఒకవేళ (st == ఖాళీ || keytype < 0 || (కొలత_t)keytype >= st->nkeys ||
	    st->pubkeys == ఖాళీ || st->pubkeys[keytype] == ఖాళీ)
		abort();
	తిరిగి st->pubkeys[keytype];
}

స్థిర నిర్మాణం sshkey *
get_privkey(నిర్మాణం shared_state *st, పూర్ణాంకం keytype)
{
	ఒకవేళ (st == ఖాళీ || keytype < 0 || (కొలత_t)keytype >= st->nkeys ||
	    st->privkeys == ఖాళీ || st->privkeys[keytype] == ఖాళీ)
		abort();
	తిరిగి st->privkeys[keytype];
}

స్థిర పూర్ణాంకం
build_proposal_side(అక్షరం **బహిర్గతం, స్థిరరాశి అక్షరం *defaults[PROPOSAL_MAX],
    స్థిరరాశి అక్షరం *kex, స్థిరరాశి అక్షరం *keyname,
    స్థిరరాశి అక్షరం *cipher, స్థిరరాశి అక్షరం *mac, స్థిరరాశి అక్షరం *comp)
{
	పూర్ణాంకం i;
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		స్థిరరాశి అక్షరం *ccp = defaults[i];
#నిర్వచితమైతే CIPHER_NONE_AVAIL
		ఒకవేళ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#అయితే_ముగింపు
		ఒకవేళ (i == PROPOSAL_SERVER_HOST_కీలకం_ALGS)
			ccp = keyname;
		లేకపోతే ఒకవేళ (i == PROPOSAL_KEX_ALGS && kex != ఖాళీ)
			ccp = kex;
		లేకపోతే ఒకవేళ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ఖాళీ)
			ccp = cipher;
		లేకపోతే ఒకవేళ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ఖాళీ)
			ccp = mac;
		లేకపోతే ఒకవేళ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ఖాళీ)
			ccp = comp;
		ఒకవేళ ((బహిర్గతం[i] = strdup(ccp)) == ఖాళీ)
			తిరిగి -1;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
do_kex_with_కీలకం(నిర్మాణం shared_state *st, నిర్మాణం test_state *ts,
    స్థిరరాశి అక్షరం *kex, పూర్ణాంకం keytype, స్థిరరాశి నిర్మాణం kex_overrides *ov)
{
	నిర్మాణం ssh *client = ఖాళీ, *server = ఖాళీ;
	నిర్మాణం sshkey *privkey = ఖాళీ, *pubkey = ఖాళీ;
	నిర్మాణం sshbuf *state = ఖాళీ;
	నిర్మాణం kex_params kex_params;
	స్థిరరాశి అక్షరం *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *myproposal[PROPOSAL_MAX] = {0};
	అక్షరం *keyname = ఖాళీ;
	పూర్ణాంకం i, r;

	ts->లోపలికి = ts->జ్యా = ఖాళీ;
	ఒకవేళ (ts->c_template != ఖాళీ &&
	    (ts->లోపలికి = sshbuf_fromb(ts->c_template)) == ఖాళీ)
		abort();
	ఒకవేళ (ts->s_template != ఖాళీ &&
	    (ts->జ్యా = sshbuf_fromb(ts->s_template)) == ఖాళీ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ఒకవేళ (ts->లోపలికి != ఖాళీ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->లోపలికి));
	} లేకపోతే ఒకవేళ (ts->జ్యా != ఖాళీ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->జ్యా));
	} లేకపోతే
		debug_f("%s %s noclobber", kex, keyname);

	ఒకవేళ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ఖాళీ,
	    ov ? ov->mac : ఖాళీ,
	    ov ? ov->comp : ఖాళీ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు fail;
	}
	జ్ఞాపకం_నకలు(kex_params.proposal, myproposal, పరిమాణం(myproposal));
	ఒకవేళ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = ssh_కూడు_hostkey(server, privkey)) != 0 ||
	    (r = ssh_కూడు_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = నిరంతరం_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		వెళ్ళు fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(myproposal[i]);
	sshbuf_free(ts->జ్యా);
	sshbuf_free(ts->లోపలికి);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	విడుదల(keyname);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
prepare_కీలకం(నిర్మాణం shared_state *st, పూర్ణాంకం kt, పూర్ణాంకం బిట్లు)
{
	స్థిరరాశి అక్షరం *pubstr = ఖాళీ;
	స్థిరరాశి అక్షరం *privstr = ఖాళీ;
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *privkey = ఖాళీ, *pubkey = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r;

	ఎంపిక (kt) {
	స్థితి కీలకం_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ఆపు;
	స్థితి కీలకం_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ఆపు;
	స్థితి కీలకం_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ఆపు;
	అప్రమేయ:
		abort();
	}
	ఒకవేళ ((b = sshbuf_from(privstr, అక్షరశ్రేణి_పొడవు(privstr))) == ఖాళీ)
		abort();
	ఒకవేళ ((r = sshkey_parse_వ్యక్తిగత_fileblob(b, "", &privkey, ఖాళీ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ఒకవేళ ((pubkey = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		abort();
	ఒకవేళ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	విడుదల(tmp);

	store_కీలకం(st, pubkey, privkey);
	తిరిగి 0;
}

#ఒకవేళ defined(STANDALONE)

#ఒకవేళ 0 /* use this if generating new keys to embed above */
స్థిర పూర్ణాంకం
prepare_కీలకం(నిర్మాణం shared_state *st, పూర్ణాంకం keytype, పూర్ణాంకం బిట్లు)
{
	నిర్మాణం sshkey *privkey = ఖాళీ, *pubkey = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_generate(keytype, బిట్లు, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_కీలకం(st, pubkey, privkey);
	తిరిగి 0;
}
#అయితే_ముగింపు

పూర్ణాంకం ప్రధాన(శూన్య)
{
	స్థిర నిర్మాణం shared_state *st;
	నిర్మాణం test_state *ts;
	స్థిరరాశి పూర్ణాంకం keytypes[] = { కీలకం_RSA, కీలకం_ECDSA, కీలకం_ED25519, -1 };
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ఖాళీ,
	};
	పూర్ణాంకం i, j;
	అక్షరం *మార్గం;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ఒకవేళ (st == ఖాళీ) {
		st = (నిర్మాణం shared_state *)xcalloc(1, పరిమాణం(*st));
		prepare_కీలకాలు(st);
	}
	/* Run each kex method for each key and save client/server packets */
	కొరకు (i = 0; keytypes[i] != -1; i++) {
		కొరకు (j = 0; kextypes[j] != ఖాళీ; j++) {
			ts = (నిర్మాణం test_state *)xcalloc(1, పరిమాణం(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_కీలకం(st, ts, kextypes[j], keytypes[i], ఖాళీ);
			xasprintf(&మార్గం, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", మార్గం);
			ఒకవేళ ((f = fopen(మార్గం, "wb+")) == ఖాళీ)
				abort();
			ఒకవేళ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			విడుదల(మార్గం);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&మార్గం, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", మార్గం);
			ఒకవేళ ((f = fopen(మార్గం, "wb+")) == ఖాళీ)
				abort();
			ఒకవేళ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			విడుదల(మార్గం);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			విడుదల(ts);
		}
	}
	కొరకు (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&మార్గం, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", మార్గం);
		ఒకవేళ (sshkey_save_వ్యక్తిగత(st->privkeys[keytypes[i]], మార్గం,
		    "", "", SSHKEY_వ్యక్తిగత_OPENSSH, ఖాళీ, 0) != 0)
			abort();
		విడుదల(మార్గం);
		xasprintf(&మార్గం, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", మార్గం);
		ఒకవేళ (sshkey_save_ప్రజా(st->pubkeys[keytypes[i]], మార్గం, "") != 0)
			abort();
		విడుదల(మార్గం);
	}
}
#లేకపోతే /* !STANDALONE */
స్థిర శూన్య
do_kex(నిర్మాణం shared_state *st, నిర్మాణం test_state *ts, స్థిరరాశి అక్షరం *kex)
{
	do_kex_with_కీలకం(st, ts, kex, కీలకం_RSA, ఖాళీ);
	do_kex_with_కీలకం(st, ts, kex, కీలకం_ECDSA, ఖాళీ);
	do_kex_with_కీలకం(st, ts, kex, కీలకం_ED25519, ఖాళీ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
స్థిర శూన్య
kex_extras(నిర్మాణం shared_state *st, నిర్మాణం test_state *ts)
{
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ఖాళీ,
	};
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ఖాళీ,
	};
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి comps[] = {
		"zlib@openssh.com",
		"zlib",
		ఖాళీ,
	};
	స్థిరరాశి అక్షరం *kex = "curve25519-sha256@libssh.org";
	పూర్ణాంకం i;

	కొరకు (i = 0; ciphers[i] != ఖాళీ; i++) {
		నిర్మాణం kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_కీలకం(st, ts, kex, కీలకం_ED25519, &ov);
	}
	కొరకు (i = 0; macs[i] != ఖాళీ; i++) {
		నిర్మాణం kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_కీలకం(st, ts, kex, కీలకం_ED25519, &ov);
	}
	కొరకు (i = 0; comps[i] != ఖాళీ; i++) {
		నిర్మాణం kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_కీలకం(st, ts, kex, కీలకం_ED25519, &ov);
	}
}

స్థిర శూన్య
kex_tests(నిర్మాణం shared_state *st, నిర్మాణం test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* దత్తాంశం, కొలత_t కొలత)
{
	స్థిర నిర్మాణం shared_state *st;
	నిర్మాణం test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_పంక్తులు * 4];
	u_char zbuf[4096] = {0};
	స్థిర LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ఒకవేళ (st == ఖాళీ) {
		ఒకవేళ (getenv("DEBUG") != ఖాళీ || getenv("KEX_FUZZ_DEBUG") != ఖాళీ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (నిర్మాణం shared_state *)xcalloc(1, పరిమాణం(*st));
		prepare_కీలకాలు(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', పరిమాణం(crbuf));

	ts = (నిర్మాణం test_state *)xcalloc(1, పరిమాణం(*ts));
	ఒకవేళ ((ts->s_template = sshbuf_new()) == ఖాళీ ||
	    sshbuf_put(ts->s_template, దత్తాంశం, కొలత) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, పరిమాణం(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, పరిమాణం(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	విడుదల(ts);

	ts = (నిర్మాణం test_state *)xcalloc(1, పరిమాణం(*ts));
	ఒకవేళ ((ts->c_template = sshbuf_new()) == ఖాళీ ||
	    sshbuf_put(ts->c_template, దత్తాంశం, కొలత) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, పరిమాణం(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, పరిమాణం(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	విడుదల(ts);

	తిరిగి 0;
}
#అయితే_ముగింపు /* STANDALONE */
} /* extern "C" */
