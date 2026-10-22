// libfuzzer driver for key exchange fuzzing.


#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "log.h"

#അന്തര്ഭാവ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

സ്ഥിതം പൂർണ്ണസംഖ്യ prepare_താക്കോൽ(ഘടന shared_state *st, പൂർണ്ണസംഖ്യ keytype, പൂർണ്ണസംഖ്യ bits);

ഘടന shared_state {
	size_t nkeys;
	ഘടന sshkey **privkeys, **pubkeys;
};

ഘടന test_state {
	ഘടന sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ഘടന sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	ഘടന sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ഘടന kex_overrides {
	സ്ഥിരം അക്ഷരം *cipher;
	സ്ഥിരം അക്ഷരം *mac;
	സ്ഥിരം അക്ഷരം *comp;
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_send_and_receive(ഘടന ssh *from, ഘടന ssh *to,
    ഘടന sshbuf *store, പൂർണ്ണസംഖ്യ clobber, size_t *n)
{
	u_char type;
	size_t len;
	സ്ഥിരം u_char *buf;
	പൂർണ്ണസംഖ്യ r;

	വേണ്ടി (*n = 0;; (*n)++) {
		എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			തിരികെ r;
		}
		എങ്കിൽ (type != 0)
			തിരികെ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		എങ്കിൽ (len == 0)
			തിരികെ 0;
		എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			തിരികെ r;
		}
		എങ്കിൽ (store != ശൂന്യ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			തിരികെ r;
		}
		എങ്കിൽ (!clobber && (r = ssh_നിവേശം_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			തിരികെ r;
		}
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന test_state *ts, ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	എങ്കിൽ (ts->sin != ശൂന്യ) {
		എങ്കിൽ ((r = ssh_നിവേശം_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			തിരികെ r;
		}
		sshbuf_reset(ts->sin);
	}
	എങ്കിൽ (ts->cin != ശൂന്യ) {
		എങ്കിൽ ((r = ssh_നിവേശം_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			തിരികെ r;
		}
		sshbuf_reset(ts->cin);
	}
	ആകുമ്പോൾ (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		എങ്കിൽ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != ശൂന്യ, &sn)) != 0) {
			debug_fr(r, "S->C");
			നിർത്തുക;
		}
		debug_f("C:");
		എങ്കിൽ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != ശൂന്യ, &cn)) != 0) {
			debug_fr(r, "C->S");
			നിർത്തുക;
		}
		എങ്കിൽ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			നിർത്തുക;
		}
	}
	debug_fr(r, "done");
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
store_താക്കോൽ(ഘടന shared_state *st, ഘടന sshkey *pubkey,
    ഘടന sshkey *privkey)
{
	എങ്കിൽ (st == ശൂന്യ || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ശൂന്യ))
		abort();
	എങ്കിൽ ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ഘടന sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, വലുപ്പം(*st->pubkeys));
		st->privkeys = (ഘടന sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, വലുപ്പം(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
prepare_താക്കോലുകൾ(ഘടന shared_state *st)
{
	എങ്കിൽ (prepare_താക്കോൽ(st, താക്കോൽ_RSA, 2048) != 0 ||
	    prepare_താക്കോൽ(st, താക്കോൽ_ECDSA, 256) != 0 ||
	    prepare_താക്കോൽ(st, താക്കോൽ_ED25519, 256) != 0) {
		error_f("key prepare failed");
		തിരികെ -1;
	}
	തിരികെ 0;
}

സ്ഥിതം ഘടന sshkey *
get_pubkey(ഘടന shared_state *st, പൂർണ്ണസംഖ്യ keytype)
{
	എങ്കിൽ (st == ശൂന്യ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == ശൂന്യ || st->pubkeys[keytype] == ശൂന്യ)
		abort();
	തിരികെ st->pubkeys[keytype];
}

സ്ഥിതം ഘടന sshkey *
get_privkey(ഘടന shared_state *st, പൂർണ്ണസംഖ്യ keytype)
{
	എങ്കിൽ (st == ശൂന്യ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == ശൂന്യ || st->privkeys[keytype] == ശൂന്യ)
		abort();
	തിരികെ st->privkeys[keytype];
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
build_proposal_side(അക്ഷരം **out, സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX],
    സ്ഥിരം അക്ഷരം *kex, സ്ഥിരം അക്ഷരം *keyname,
    സ്ഥിരം അക്ഷരം *cipher, സ്ഥിരം അക്ഷരം *mac, സ്ഥിരം അക്ഷരം *comp)
{
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			ccp = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS && kex != ശൂന്യ)
			ccp = kex;
		അല്ലെങ്കിൽ എങ്കിൽ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ശൂന്യ)
			ccp = cipher;
		അല്ലെങ്കിൽ എങ്കിൽ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ശൂന്യ)
			ccp = mac;
		അല്ലെങ്കിൽ എങ്കിൽ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ശൂന്യ)
			ccp = comp;
		എങ്കിൽ ((out[i] = strdup(ccp)) == ശൂന്യ)
			തിരികെ -1;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_kex_with_താക്കോൽ(ഘടന shared_state *st, ഘടന test_state *ts,
    സ്ഥിരം അക്ഷരം *kex, പൂർണ്ണസംഖ്യ keytype, സ്ഥിരം ഘടന kex_overrides *ov)
{
	ഘടന ssh *client = ശൂന്യ, *server = ശൂന്യ;
	ഘടന sshkey *privkey = ശൂന്യ, *pubkey = ശൂന്യ;
	ഘടന sshbuf *state = ശൂന്യ;
	ഘടന kex_params kex_params;
	സ്ഥിരം അക്ഷരം *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *myproposal[PROPOSAL_MAX] = {0};
	അക്ഷരം *keyname = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, r;

	ts->cin = ts->sin = ശൂന്യ;
	എങ്കിൽ (ts->c_template != ശൂന്യ &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == ശൂന്യ)
		abort();
	എങ്കിൽ (ts->s_template != ശൂന്യ &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == ശൂന്യ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	എങ്കിൽ (ts->cin != ശൂന്യ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} അല്ലെങ്കിൽ എങ്കിൽ (ts->sin != ശൂന്യ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} അല്ലെങ്കിൽ
		debug_f("%s %s noclobber", kex, keyname);

	എങ്കിൽ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ശൂന്യ,
	    ov ? ov->mac : ശൂന്യ,
	    ov ? ov->comp : ശൂന്യ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക fail;
	}
	memcpy(kex_params.proposal, myproposal, വലുപ്പം(myproposal));
	എങ്കിൽ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		പോകുക fail;
	}
	എങ്കിൽ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		പോകുക fail;
	}
	എങ്കിൽ ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		പോകുക fail;
	}
	എങ്കിൽ ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		പോകുക fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	സ്വതന്ത്രം(keyname);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
prepare_താക്കോൽ(ഘടന shared_state *st, പൂർണ്ണസംഖ്യ kt, പൂർണ്ണസംഖ്യ bits)
{
	സ്ഥിരം അക്ഷരം *pubstr = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *privstr = ശൂന്യ;
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *privkey = ശൂന്യ, *pubkey = ശൂന്യ;
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	തിരഞ്ഞെടുപ്പ് (kt) {
	അവസ്ഥ താക്കോൽ_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		abort();
	}
	എങ്കിൽ ((b = sshbuf_from(privstr, strlen(privstr))) == ശൂന്യ)
		abort();
	എങ്കിൽ ((r = sshkey_parse_private_fileblob(b, "", &privkey, ശൂന്യ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	എങ്കിൽ ((pubkey = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		abort();
	എങ്കിൽ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	സ്വതന്ത്രം(tmp);

	store_താക്കോൽ(st, pubkey, privkey);
	തിരികെ 0;
}

#എങ്കിൽ defined(STANDALONE)

#എങ്കിൽ 0 /* use this if generating new keys to embed above */
സ്ഥിതം പൂർണ്ണസംഖ്യ
prepare_താക്കോൽ(ഘടന shared_state *st, പൂർണ്ണസംഖ്യ keytype, പൂർണ്ണസംഖ്യ bits)
{
	ഘടന sshkey *privkey = ശൂന്യ, *pubkey = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	എങ്കിൽ ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_താക്കോൽ(st, pubkey, privkey);
	തിരികെ 0;
}
#endif

പൂർണ്ണസംഖ്യ പ്രധാന(ശൂന്യം)
{
	സ്ഥിതം ഘടന shared_state *st;
	ഘടന test_state *ts;
	സ്ഥിരം പൂർണ്ണസംഖ്യ keytypes[] = { താക്കോൽ_RSA, താക്കോൽ_ECDSA, താക്കോൽ_ED25519, -1 };
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ശൂന്യ,
	};
	പൂർണ്ണസംഖ്യ i, j;
	അക്ഷരം *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	എങ്കിൽ (st == ശൂന്യ) {
		st = (ഘടന shared_state *)xcalloc(1, വലുപ്പം(*st));
		prepare_താക്കോലുകൾ(st);
	}
	/* Run each kex method for each key and save client/server packets */
	വേണ്ടി (i = 0; keytypes[i] != -1; i++) {
		വേണ്ടി (j = 0; kextypes[j] != ശൂന്യ; j++) {
			ts = (ഘടന test_state *)xcalloc(1, വലുപ്പം(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_താക്കോൽ(st, ts, kextypes[j], keytypes[i], ശൂന്യ);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			എങ്കിൽ ((f = fopen(path, "wb+")) == ശൂന്യ)
				abort();
			എങ്കിൽ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			സ്വതന്ത്രം(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			എങ്കിൽ ((f = fopen(path, "wb+")) == ശൂന്യ)
				abort();
			എങ്കിൽ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			സ്വതന്ത്രം(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			സ്വതന്ത്രം(ts);
		}
	}
	വേണ്ടി (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		എങ്കിൽ (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, ശൂന്യ, 0) != 0)
			abort();
		സ്വതന്ത്രം(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		എങ്കിൽ (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		സ്വതന്ത്രം(path);
	}
}
#അല്ലെങ്കിൽ /* !STANDALONE */
സ്ഥിതം ശൂന്യം
do_kex(ഘടന shared_state *st, ഘടന test_state *ts, സ്ഥിരം അക്ഷരം *kex)
{
	do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_RSA, ശൂന്യ);
	do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_ECDSA, ശൂന്യ);
	do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_ED25519, ശൂന്യ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
സ്ഥിതം ശൂന്യം
kex_extras(ഘടന shared_state *st, ഘടന test_state *ts)
{
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ശൂന്യ,
	};
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ശൂന്യ,
	};
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം comps[] = {
		"zlib@openssh.com",
		"zlib",
		ശൂന്യ,
	};
	സ്ഥിരം അക്ഷരം *kex = "curve25519-sha256@libssh.org";
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; ciphers[i] != ശൂന്യ; i++) {
		ഘടന kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_ED25519, &ov);
	}
	വേണ്ടി (i = 0; macs[i] != ശൂന്യ; i++) {
		ഘടന kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_ED25519, &ov);
	}
	വേണ്ടി (i = 0; comps[i] != ശൂന്യ; i++) {
		ഘടന kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_താക്കോൽ(st, ts, kex, താക്കോൽ_ED25519, &ov);
	}
}

സ്ഥിതം ശൂന്യം
kex_tests(ഘടന shared_state *st, ഘടന test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* data, size_t size)
{
	സ്ഥിതം ഘടന shared_state *st;
	ഘടന test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_വരികൾ * 4];
	u_char zbuf[4096] = {0};
	സ്ഥിതം LogLevel loglevel = SYSLOG_LEVEL_INFO;

	എങ്കിൽ (st == ശൂന്യ) {
		എങ്കിൽ (getenv("DEBUG") != ശൂന്യ || getenv("KEX_FUZZ_DEBUG") != ശൂന്യ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ഘടന shared_state *)xcalloc(1, വലുപ്പം(*st));
		prepare_താക്കോലുകൾ(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', വലുപ്പം(crbuf));

	ts = (ഘടന test_state *)xcalloc(1, വലുപ്പം(*ts));
	എങ്കിൽ ((ts->s_template = sshbuf_new()) == ശൂന്യ ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, വലുപ്പം(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, വലുപ്പം(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	സ്വതന്ത്രം(ts);

	ts = (ഘടന test_state *)xcalloc(1, വലുപ്പം(*ts));
	എങ്കിൽ ((ts->c_template = sshbuf_new()) == ശൂന്യ ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, വലുപ്പം(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, വലുപ്പം(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	സ്വതന്ത്രം(ts);

	തിരികെ 0;
}
#endif /* STANDALONE */
} /* extern "C" */
