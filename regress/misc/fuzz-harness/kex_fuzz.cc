// libfuzzer driver for key exchange fuzzing.


#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

ਸਥਿਰ ਪੂਰਨ prepare_ਕੁੰਜੀ(ਬਣਤਰ shared_state *st, ਪੂਰਨ keytype, ਪੂਰਨ ਬਿੱਟ);

ਬਣਤਰ shared_state {
	ਮਾਪ_t nkeys;
	ਬਣਤਰ sshkey **privkeys, **pubkeys;
};

ਬਣਤਰ test_state {
	ਬਣਤਰ sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ਬਣਤਰ sshbuf *ਜੀਵਾ, *ਅੰਦਰ; /* input; setup per-test in do_kex_with_key */
	ਬਣਤਰ sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ਬਣਤਰ kex_overrides {
	ਅਚਲ ਅੱਖਰ *cipher;
	ਅਚਲ ਅੱਖਰ *mac;
	ਅਚਲ ਅੱਖਰ *comp;
};

ਸਥਿਰ ਪੂਰਨ
do_send_and_receive(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ,
    ਬਣਤਰ sshbuf *store, ਪੂਰਨ clobber, ਮਾਪ_t *n)
{
	u_char type;
	ਮਾਪ_t len;
	ਅਚਲ u_char *buf;
	ਪੂਰਨ r;

	ਲਈ (*n = 0;; (*n)++) {
		ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ਵਾਪਸ r;
		}
		ਜੇ (type != 0)
			ਵਾਪਸ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ਜੇ (len == 0)
			ਵਾਪਸ 0;
		ਜੇ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ਵਾਪਸ r;
		}
		ਜੇ (store != ਨਿਰਾ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ਵਾਪਸ r;
		}
		ਜੇ (!clobber && (r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ਵਾਪਸ r;
		}
	}
}

ਸਥਿਰ ਪੂਰਨ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ test_state *ts, ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r = 0;
	ਮਾਪ_t cn, sn;

	/* If fuzzing, replace server/client input */
	ਜੇ (ts->ਜੀਵਾ != ਨਿਰਾ) {
		ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(server, sshbuf_ptr(ts->ਜੀਵਾ),
		    sshbuf_len(ts->ਜੀਵਾ))) != 0) {
			error_fr(r, "ssh_input_append");
			ਵਾਪਸ r;
		}
		sshbuf_reset(ts->ਜੀਵਾ);
	}
	ਜੇ (ts->ਅੰਦਰ != ਨਿਰਾ) {
		ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(client, sshbuf_ptr(ts->ਅੰਦਰ),
		    sshbuf_len(ts->ਅੰਦਰ))) != 0) {
			error_fr(r, "ssh_input_append");
			ਵਾਪਸ r;
		}
		sshbuf_reset(ts->ਅੰਦਰ);
	}
	ਜਦੋਂ (!server->kex->ਪੂਰਾ || !client->kex->ਪੂਰਾ) {
		cn = sn = 0;
		debug_f("S:");
		ਜੇ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->ਅੰਦਰ != ਨਿਰਾ, &sn)) != 0) {
			debug_fr(r, "S->C");
			ਰੋਕੋ;
		}
		debug_f("C:");
		ਜੇ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->ਜੀਵਾ != ਨਿਰਾ, &cn)) != 0) {
			debug_fr(r, "C->S");
			ਰੋਕੋ;
		}
		ਜੇ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ਰੋਕੋ;
		}
	}
	debug_fr(r, "done");
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
store_ਕੁੰਜੀ(ਬਣਤਰ shared_state *st, ਬਣਤਰ sshkey *pubkey,
    ਬਣਤਰ sshkey *privkey)
{
	ਜੇ (st == ਨਿਰਾ || pubkey->type < 0 || pubkey->type > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ ||
	    privkey->type != pubkey->type ||
	    ((ਮਾਪ_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ਨਿਰਾ))
		abort();
	ਜੇ ((ਮਾਪ_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ਬਣਤਰ sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, ਆਕਾਰ(*st->pubkeys));
		st->privkeys = (ਬਣਤਰ sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, ਆਕਾਰ(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ਸਥਿਰ ਪੂਰਨ
prepare_ਕੁੰਜੀਆਂ(ਬਣਤਰ shared_state *st)
{
	ਜੇ (prepare_ਕੁੰਜੀ(st, ਕੁੰਜੀ_RSA, 2048) != 0 ||
	    prepare_ਕੁੰਜੀ(st, ਕੁੰਜੀ_ECDSA, 256) != 0 ||
	    prepare_ਕੁੰਜੀ(st, ਕੁੰਜੀ_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
get_pubkey(ਬਣਤਰ shared_state *st, ਪੂਰਨ keytype)
{
	ਜੇ (st == ਨਿਰਾ || keytype < 0 || (ਮਾਪ_t)keytype >= st->nkeys ||
	    st->pubkeys == ਨਿਰਾ || st->pubkeys[keytype] == ਨਿਰਾ)
		abort();
	ਵਾਪਸ st->pubkeys[keytype];
}

ਸਥਿਰ ਬਣਤਰ sshkey *
get_privkey(ਬਣਤਰ shared_state *st, ਪੂਰਨ keytype)
{
	ਜੇ (st == ਨਿਰਾ || keytype < 0 || (ਮਾਪ_t)keytype >= st->nkeys ||
	    st->privkeys == ਨਿਰਾ || st->privkeys[keytype] == ਨਿਰਾ)
		abort();
	ਵਾਪਸ st->privkeys[keytype];
}

ਸਥਿਰ ਪੂਰਨ
build_proposal_side(ਅੱਖਰ **ਬਾਹਰਲਾ, ਅਚਲ ਅੱਖਰ *defaults[PROPOSAL_MAX],
    ਅਚਲ ਅੱਖਰ *kex, ਅਚਲ ਅੱਖਰ *keyname,
    ਅਚਲ ਅੱਖਰ *cipher, ਅਚਲ ਅੱਖਰ *mac, ਅਚਲ ਅੱਖਰ *comp)
{
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਅਚਲ ਅੱਖਰ *ccp = defaults[i];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CIPHER_NONE_AVAIL
		ਜੇ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#ਜੇ_ਅੰਤ
		ਜੇ (i == PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS)
			ccp = keyname;
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_KEX_ALGS && kex != ਨਿਰਾ)
			ccp = kex;
		ਨਹੀਂਤਾਂ ਜੇ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ਨਿਰਾ)
			ccp = cipher;
		ਨਹੀਂਤਾਂ ਜੇ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ਨਿਰਾ)
			ccp = mac;
		ਨਹੀਂਤਾਂ ਜੇ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ਨਿਰਾ)
			ccp = comp;
		ਜੇ ((ਬਾਹਰਲਾ[i] = strdup(ccp)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
do_kex_with_ਕੁੰਜੀ(ਬਣਤਰ shared_state *st, ਬਣਤਰ test_state *ts,
    ਅਚਲ ਅੱਖਰ *kex, ਪੂਰਨ keytype, ਅਚਲ ਬਣਤਰ kex_overrides *ov)
{
	ਬਣਤਰ ssh *client = ਨਿਰਾ, *server = ਨਿਰਾ;
	ਬਣਤਰ sshkey *privkey = ਨਿਰਾ, *pubkey = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *state = ਨਿਰਾ;
	ਬਣਤਰ kex_params kex_params;
	ਅਚਲ ਅੱਖਰ *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *myproposal[PROPOSAL_MAX] = {0};
	ਅੱਖਰ *keyname = ਨਿਰਾ;
	ਪੂਰਨ i, r;

	ts->ਅੰਦਰ = ts->ਜੀਵਾ = ਨਿਰਾ;
	ਜੇ (ts->c_template != ਨਿਰਾ &&
	    (ts->ਅੰਦਰ = sshbuf_fromb(ts->c_template)) == ਨਿਰਾ)
		abort();
	ਜੇ (ts->s_template != ਨਿਰਾ &&
	    (ts->ਜੀਵਾ = sshbuf_fromb(ts->s_template)) == ਨਿਰਾ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ਜੇ (ts->ਅੰਦਰ != ਨਿਰਾ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->ਅੰਦਰ));
	} ਨਹੀਂਤਾਂ ਜੇ (ts->ਜੀਵਾ != ਨਿਰਾ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->ਜੀਵਾ));
	} ਨਹੀਂਤਾਂ
		debug_f("%s %s noclobber", kex, keyname);

	ਜੇ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ਨਿਰਾ,
	    ov ? ov->mac : ਨਿਰਾ,
	    ov ? ov->comp : ਨਿਰਾ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ fail;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kex_params.proposal, myproposal, ਆਕਾਰ(myproposal));
	ਜੇ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		ਜਾਓ fail;
	}
	ਜੇ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		ਜਾਓ fail;
	}
	ਜੇ ((r = ssh_ਜੋੜੋ_hostkey(server, privkey)) != 0 ||
	    (r = ssh_ਜੋੜੋ_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		ਜਾਓ fail;
	}
	ਜੇ ((r = ਲੜੀਵਾਰ_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		ਜਾਓ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(myproposal[i]);
	sshbuf_free(ts->ਜੀਵਾ);
	sshbuf_free(ts->ਅੰਦਰ);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	ਮੁਕਤ(keyname);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
prepare_ਕੁੰਜੀ(ਬਣਤਰ shared_state *st, ਪੂਰਨ kt, ਪੂਰਨ ਬਿੱਟ)
{
	ਅਚਲ ਅੱਖਰ *pubstr = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *privstr = ਨਿਰਾ;
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *privkey = ਨਿਰਾ, *pubkey = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਚੋਣ (kt) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ਰੋਕੋ;
	ਮੂਲ:
		abort();
	}
	ਜੇ ((b = sshbuf_from(privstr, ਲੜੀ_ਲੰਬਾਈ(privstr))) == ਨਿਰਾ)
		abort();
	ਜੇ ((r = sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &privkey, ਨਿਰਾ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ਜੇ ((pubkey = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		abort();
	ਜੇ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	ਮੁਕਤ(tmp);

	store_ਕੁੰਜੀ(st, pubkey, privkey);
	ਵਾਪਸ 0;
}

#ਜੇ defined(STANDALONE)

#ਜੇ 0 /* use this if generating new keys to embed above */
ਸਥਿਰ ਪੂਰਨ
prepare_ਕੁੰਜੀ(ਬਣਤਰ shared_state *st, ਪੂਰਨ keytype, ਪੂਰਨ ਬਿੱਟ)
{
	ਬਣਤਰ sshkey *privkey = ਨਿਰਾ, *pubkey = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_generate(keytype, ਬਿੱਟ, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ਕੁੰਜੀ(st, pubkey, privkey);
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ ਮੁੱਖ(ਖਾਲੀ)
{
	ਸਥਿਰ ਬਣਤਰ shared_state *st;
	ਬਣਤਰ test_state *ts;
	ਅਚਲ ਪੂਰਨ keytypes[] = { ਕੁੰਜੀ_RSA, ਕੁੰਜੀ_ECDSA, ਕੁੰਜੀ_ED25519, -1 };
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ਨਿਰਾ,
	};
	ਪੂਰਨ i, j;
	ਅੱਖਰ *ਰਸਤਾ;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ਜੇ (st == ਨਿਰਾ) {
		st = (ਬਣਤਰ shared_state *)xcalloc(1, ਆਕਾਰ(*st));
		prepare_ਕੁੰਜੀਆਂ(st);
	}
	/* Run each kex method for each key and save client/server packets */
	ਲਈ (i = 0; keytypes[i] != -1; i++) {
		ਲਈ (j = 0; kextypes[j] != ਨਿਰਾ; j++) {
			ts = (ਬਣਤਰ test_state *)xcalloc(1, ਆਕਾਰ(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ਕੁੰਜੀ(st, ts, kextypes[j], keytypes[i], ਨਿਰਾ);
			xasprintf(&ਰਸਤਾ, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", ਰਸਤਾ);
			ਜੇ ((f = fopen(ਰਸਤਾ, "wb+")) == ਨਿਰਾ)
				abort();
			ਜੇ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			ਮੁਕਤ(ਰਸਤਾ);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&ਰਸਤਾ, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", ਰਸਤਾ);
			ਜੇ ((f = fopen(ਰਸਤਾ, "wb+")) == ਨਿਰਾ)
				abort();
			ਜੇ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			ਮੁਕਤ(ਰਸਤਾ);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			ਮੁਕਤ(ts);
		}
	}
	ਲਈ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&ਰਸਤਾ, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", ਰਸਤਾ);
		ਜੇ (sshkey_save_ਨਿੱਜੀ(st->privkeys[keytypes[i]], ਰਸਤਾ,
		    "", "", SSHKEY_ਨਿੱਜੀ_OPENSSH, ਨਿਰਾ, 0) != 0)
			abort();
		ਮੁਕਤ(ਰਸਤਾ);
		xasprintf(&ਰਸਤਾ, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", ਰਸਤਾ);
		ਜੇ (sshkey_save_ਜਨਤਕ(st->pubkeys[keytypes[i]], ਰਸਤਾ, "") != 0)
			abort();
		ਮੁਕਤ(ਰਸਤਾ);
	}
}
#ਨਹੀਂਤਾਂ /* !STANDALONE */
ਸਥਿਰ ਖਾਲੀ
do_kex(ਬਣਤਰ shared_state *st, ਬਣਤਰ test_state *ts, ਅਚਲ ਅੱਖਰ *kex)
{
	do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_RSA, ਨਿਰਾ);
	do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_ECDSA, ਨਿਰਾ);
	do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_ED25519, ਨਿਰਾ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ਸਥਿਰ ਖਾਲੀ
kex_extras(ਬਣਤਰ shared_state *st, ਬਣਤਰ test_state *ts)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ਨਿਰਾ,
	};
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ਨਿਰਾ,
	};
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ * ਅਚਲ comps[] = {
		"zlib@openssh.com",
		"zlib",
		ਨਿਰਾ,
	};
	ਅਚਲ ਅੱਖਰ *kex = "curve25519-sha256@libssh.org";
	ਪੂਰਨ i;

	ਲਈ (i = 0; ciphers[i] != ਨਿਰਾ; i++) {
		ਬਣਤਰ kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_ED25519, &ov);
	}
	ਲਈ (i = 0; macs[i] != ਨਿਰਾ; i++) {
		ਬਣਤਰ kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_ED25519, &ov);
	}
	ਲਈ (i = 0; comps[i] != ਨਿਰਾ; i++) {
		ਬਣਤਰ kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ਕੁੰਜੀ(st, ts, kex, ਕੁੰਜੀ_ED25519, &ov);
	}
}

ਸਥਿਰ ਖਾਲੀ
kex_tests(ਬਣਤਰ shared_state *st, ਬਣਤਰ test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਸਥਿਰ ਬਣਤਰ shared_state *st;
	ਬਣਤਰ test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_ਸਤਰਾਂ * 4];
	u_char zbuf[4096] = {0};
	ਸਥਿਰ LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ਜੇ (st == ਨਿਰਾ) {
		ਜੇ (getenv("DEBUG") != ਨਿਰਾ || getenv("KEX_FUZZ_DEBUG") != ਨਿਰਾ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ਬਣਤਰ shared_state *)xcalloc(1, ਆਕਾਰ(*st));
		prepare_ਕੁੰਜੀਆਂ(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', ਆਕਾਰ(crbuf));

	ts = (ਬਣਤਰ test_state *)xcalloc(1, ਆਕਾਰ(*ts));
	ਜੇ ((ts->s_template = sshbuf_new()) == ਨਿਰਾ ||
	    sshbuf_put(ts->s_template, ਅੰਕੜੇ, ਮਾਪ) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, ਆਕਾਰ(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, ਆਕਾਰ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	ਮੁਕਤ(ts);

	ts = (ਬਣਤਰ test_state *)xcalloc(1, ਆਕਾਰ(*ts));
	ਜੇ ((ts->c_template = sshbuf_new()) == ਨਿਰਾ ||
	    sshbuf_put(ts->c_template, ਅੰਕੜੇ, ਮਾਪ) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, ਆਕਾਰ(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, ਆਕਾਰ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	ਮੁਕਤ(ts);

	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* STANDALONE */
} /* extern "C" */
