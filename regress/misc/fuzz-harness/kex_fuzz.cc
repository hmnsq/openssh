// libfuzzer driver for key exchange fuzzing.


#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય "C" {

#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "log.h"

#અન્તર્ભાવ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

સ્થિર પૂર્ણાંક prepare_ચાવી(સંરચના shared_state *st, પૂર્ણાંક keytype, પૂર્ણાંક bits);

સંરચના shared_state {
	size_t nkeys;
	સંરચના sshkey **privkeys, **pubkeys;
};

સંરચના test_state {
	સંરચના sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	સંરચના sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	સંરચના sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
સંરચના kex_overrides {
	અચલ અક્ષર *cipher;
	અચલ અક્ષર *mac;
	અચલ અક્ષર *comp;
};

સ્થિર પૂર્ણાંક
do_send_and_receive(સંરચના ssh *from, સંરચના ssh *to,
    સંરચના sshbuf *store, પૂર્ણાંક clobber, size_t *n)
{
	u_char type;
	size_t len;
	અચલ u_char *buf;
	પૂર્ણાંક r;

	માટે (*n = 0;; (*n)++) {
		જો ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			પાછા r;
		}
		જો (type != 0)
			પાછા 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		જો (len == 0)
			પાછા 0;
		જો ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			પાછા r;
		}
		જો (store != ખાલી && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			પાછા r;
		}
		જો (!clobber && (r = ssh_આગત_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			પાછા r;
		}
	}
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના test_state *ts, સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	જો (ts->sin != ખાલી) {
		જો ((r = ssh_આગત_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			પાછા r;
		}
		sshbuf_reset(ts->sin);
	}
	જો (ts->cin != ખાલી) {
		જો ((r = ssh_આગત_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			પાછા r;
		}
		sshbuf_reset(ts->cin);
	}
	જ્યારે (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		જો ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != ખાલી, &sn)) != 0) {
			debug_fr(r, "S->C");
			તોડો;
		}
		debug_f("C:");
		જો ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != ખાલી, &cn)) != 0) {
			debug_fr(r, "C->S");
			તોડો;
		}
		જો (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			તોડો;
		}
	}
	debug_fr(r, "done");
	પાછા r;
}

સ્થિર શૂન્ય
store_ચાવી(સંરચના shared_state *st, સંરચના sshkey *pubkey,
    સંરચના sshkey *privkey)
{
	જો (st == ખાલી || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ખાલી))
		abort();
	જો ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (સંરચના sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, કદ(*st->pubkeys));
		st->privkeys = (સંરચના sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, કદ(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

સ્થિર પૂર્ણાંક
prepare_ચાવીઓ(સંરચના shared_state *st)
{
	જો (prepare_ચાવી(st, ચાવી_RSA, 2048) != 0 ||
	    prepare_ચાવી(st, ચાવી_ECDSA, 256) != 0 ||
	    prepare_ચાવી(st, ચાવી_ED25519, 256) != 0) {
		error_f("key prepare failed");
		પાછા -1;
	}
	પાછા 0;
}

સ્થિર સંરચના sshkey *
get_pubkey(સંરચના shared_state *st, પૂર્ણાંક keytype)
{
	જો (st == ખાલી || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == ખાલી || st->pubkeys[keytype] == ખાલી)
		abort();
	પાછા st->pubkeys[keytype];
}

સ્થિર સંરચના sshkey *
get_privkey(સંરચના shared_state *st, પૂર્ણાંક keytype)
{
	જો (st == ખાલી || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == ખાલી || st->privkeys[keytype] == ખાલી)
		abort();
	પાછા st->privkeys[keytype];
}

સ્થિર પૂર્ણાંક
build_proposal_side(અક્ષર **out, અચલ અક્ષર *defaults[PROPOSAL_MAX],
    અચલ અક્ષર *kex, અચલ અક્ષર *keyname,
    અચલ અક્ષર *cipher, અચલ અક્ષર *mac, અચલ અક્ષર *comp)
{
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			ccp = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS && kex != ખાલી)
			ccp = kex;
		નહીંતર જો ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ખાલી)
			ccp = cipher;
		નહીંતર જો ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ખાલી)
			ccp = mac;
		નહીંતર જો ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ખાલી)
			ccp = comp;
		જો ((out[i] = strdup(ccp)) == ખાલી)
			પાછા -1;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
do_kex_with_ચાવી(સંરચના shared_state *st, સંરચના test_state *ts,
    અચલ અક્ષર *kex, પૂર્ણાંક keytype, અચલ સંરચના kex_overrides *ov)
{
	સંરચના ssh *client = ખાલી, *server = ખાલી;
	સંરચના sshkey *privkey = ખાલી, *pubkey = ખાલી;
	સંરચના sshbuf *state = ખાલી;
	સંરચના kex_params kex_params;
	અચલ અક્ષર *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *myproposal[PROPOSAL_MAX] = {0};
	અક્ષર *keyname = ખાલી;
	પૂર્ણાંક i, r;

	ts->cin = ts->sin = ખાલી;
	જો (ts->c_template != ખાલી &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == ખાલી)
		abort();
	જો (ts->s_template != ખાલી &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == ખાલી)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	જો (ts->cin != ખાલી) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} નહીંતર જો (ts->sin != ખાલી) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} નહીંતર
		debug_f("%s %s noclobber", kex, keyname);

	જો (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ખાલી,
	    ov ? ov->mac : ખાલી,
	    ov ? ov->comp : ખાલી) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ fail;
	}
	memcpy(kex_params.proposal, myproposal, કદ(myproposal));
	જો ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		જાઓ fail;
	}
	જો ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		જાઓ fail;
	}
	જો ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		જાઓ fail;
	}
	જો ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		જાઓ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	મુક્ત(keyname);
	પાછા r;
}

સ્થિર પૂર્ણાંક
prepare_ચાવી(સંરચના shared_state *st, પૂર્ણાંક kt, પૂર્ણાંક bits)
{
	અચલ અક્ષર *pubstr = ખાલી;
	અચલ અક્ષર *privstr = ખાલી;
	અક્ષર *tmp, *cp;
	સંરચના sshkey *privkey = ખાલી, *pubkey = ખાલી;
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r;

	પસંદગી (kt) {
	સ્થિતિ ચાવી_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		તોડો;
	સ્થિતિ ચાવી_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		તોડો;
	મૂળભૂત:
		abort();
	}
	જો ((b = sshbuf_from(privstr, strlen(privstr))) == ખાલી)
		abort();
	જો ((r = sshkey_parse_private_fileblob(b, "", &privkey, ખાલી)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	જો ((pubkey = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		abort();
	જો ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	મુક્ત(tmp);

	store_ચાવી(st, pubkey, privkey);
	પાછા 0;
}

#જો defined(STANDALONE)

#જો 0 /* use this if generating new keys to embed above */
સ્થિર પૂર્ણાંક
prepare_ચાવી(સંરચના shared_state *st, પૂર્ણાંક keytype, પૂર્ણાંક bits)
{
	સંરચના sshkey *privkey = ખાલી, *pubkey = ખાલી;
	પૂર્ણાંક r;

	જો ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	જો ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ચાવી(st, pubkey, privkey);
	પાછા 0;
}
#endif

પૂર્ણાંક મુખ્ય(શૂન્ય)
{
	સ્થિર સંરચના shared_state *st;
	સંરચના test_state *ts;
	અચલ પૂર્ણાંક keytypes[] = { ચાવી_RSA, ચાવી_ECDSA, ચાવી_ED25519, -1 };
	સ્થિર અચલ અક્ષર * અચલ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ખાલી,
	};
	પૂર્ણાંક i, j;
	અક્ષર *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	જો (st == ખાલી) {
		st = (સંરચના shared_state *)xcalloc(1, કદ(*st));
		prepare_ચાવીઓ(st);
	}
	/* Run each kex method for each key and save client/server packets */
	માટે (i = 0; keytypes[i] != -1; i++) {
		માટે (j = 0; kextypes[j] != ખાલી; j++) {
			ts = (સંરચના test_state *)xcalloc(1, કદ(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ચાવી(st, ts, kextypes[j], keytypes[i], ખાલી);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			જો ((f = fopen(path, "wb+")) == ખાલી)
				abort();
			જો (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			મુક્ત(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			જો ((f = fopen(path, "wb+")) == ખાલી)
				abort();
			જો (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			મુક્ત(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			મુક્ત(ts);
		}
	}
	માટે (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		જો (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, ખાલી, 0) != 0)
			abort();
		મુક્ત(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		જો (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		મુક્ત(path);
	}
}
#નહીંતર /* !STANDALONE */
સ્થિર શૂન્ય
do_kex(સંરચના shared_state *st, સંરચના test_state *ts, અચલ અક્ષર *kex)
{
	do_kex_with_ચાવી(st, ts, kex, ચાવી_RSA, ખાલી);
	do_kex_with_ચાવી(st, ts, kex, ચાવી_ECDSA, ખાલી);
	do_kex_with_ચાવી(st, ts, kex, ચાવી_ED25519, ખાલી);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
સ્થિર શૂન્ય
kex_extras(સંરચના shared_state *st, સંરચના test_state *ts)
{
	સ્થિર અચલ અક્ષર * અચલ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ખાલી,
	};
	સ્થિર અચલ અક્ષર * અચલ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ખાલી,
	};
	સ્થિર અચલ અક્ષર * અચલ comps[] = {
		"zlib@openssh.com",
		"zlib",
		ખાલી,
	};
	અચલ અક્ષર *kex = "curve25519-sha256@libssh.org";
	પૂર્ણાંક i;

	માટે (i = 0; ciphers[i] != ખાલી; i++) {
		સંરચના kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ચાવી(st, ts, kex, ચાવી_ED25519, &ov);
	}
	માટે (i = 0; macs[i] != ખાલી; i++) {
		સંરચના kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ચાવી(st, ts, kex, ચાવી_ED25519, &ov);
	}
	માટે (i = 0; comps[i] != ખાલી; i++) {
		સંરચના kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ચાવી(st, ts, kex, ચાવી_ED25519, &ov);
	}
}

સ્થિર શૂન્ય
kex_tests(સંરચના shared_state *st, સંરચના test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t* data, size_t size)
{
	સ્થિર સંરચના shared_state *st;
	સંરચના test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_લીટીઓ * 4];
	u_char zbuf[4096] = {0};
	સ્થિર LogLevel loglevel = SYSLOG_LEVEL_INFO;

	જો (st == ખાલી) {
		જો (getenv("DEBUG") != ખાલી || getenv("KEX_FUZZ_DEBUG") != ખાલી)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (સંરચના shared_state *)xcalloc(1, કદ(*st));
		prepare_ચાવીઓ(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', કદ(crbuf));

	ts = (સંરચના test_state *)xcalloc(1, કદ(*ts));
	જો ((ts->s_template = sshbuf_new()) == ખાલી ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, કદ(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, કદ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	મુક્ત(ts);

	ts = (સંરચના test_state *)xcalloc(1, કદ(*ts));
	જો ((ts->c_template = sshbuf_new()) == ખાલી ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, કદ(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, કદ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	મુક્ત(ts);

	પાછા 0;
}
#endif /* STANDALONE */
} /* extern "C" */
