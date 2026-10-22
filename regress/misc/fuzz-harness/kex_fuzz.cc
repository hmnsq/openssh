// libfuzzer driver for key exchange fuzzing.


#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ prepare_ಕೀಲಿ(ಸಂರಚನಾ shared_state *st, ಪೂರ್ಣಾಙ್ಕ keytype, ಪೂರ್ಣಾಙ್ಕ bits);

ಸಂರಚನಾ shared_state {
	size_t nkeys;
	ಸಂರಚನಾ sshkey **privkeys, **pubkeys;
};

ಸಂರಚನಾ test_state {
	ಸಂರಚನಾ sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ಸಂರಚನಾ sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	ಸಂರಚನಾ sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ಸಂರಚನಾ kex_overrides {
	ಧ್ರುವ ವರ್ಣ *cipher;
	ಧ್ರುವ ವರ್ಣ *mac;
	ಧ್ರುವ ವರ್ಣ *comp;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_send_and_receive(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to,
    ಸಂರಚನಾ sshbuf *store, ಪೂರ್ಣಾಙ್ಕ clobber, size_t *n)
{
	u_char type;
	size_t len;
	ಧ್ರುವ u_char *buf;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಪ್ರತಿ (*n = 0;; (*n)++) {
		ಯದಿ ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ಪ್ರತ್ಯಾಗಮ r;
		}
		ಯದಿ (type != 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ಯದಿ (len == 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ಪ್ರತ್ಯಾಗಮ r;
		}
		ಯದಿ (store != ರಿಕ್ತ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ಪ್ರತ್ಯಾಗಮ r;
		}
		ಯದಿ (!clobber && (r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ test_state *ts, ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	ಯದಿ (ts->sin != ರಿಕ್ತ) {
		ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ಪ್ರತ್ಯಾಗಮ r;
		}
		sshbuf_reset(ts->sin);
	}
	ಯದಿ (ts->cin != ರಿಕ್ತ) {
		ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ಪ್ರತ್ಯಾಗಮ r;
		}
		sshbuf_reset(ts->cin);
	}
	ಯಾವತ್ (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		ಯದಿ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != ರಿಕ್ತ, &sn)) != 0) {
			debug_fr(r, "S->C");
			ಭಙ್ಗ;
		}
		debug_f("C:");
		ಯದಿ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != ರಿಕ್ತ, &cn)) != 0) {
			debug_fr(r, "C->S");
			ಭಙ್ಗ;
		}
		ಯದಿ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ಭಙ್ಗ;
		}
	}
	debug_fr(r, "done");
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
store_ಕೀಲಿ(ಸಂರಚನಾ shared_state *st, ಸಂರಚನಾ sshkey *pubkey,
    ಸಂರಚನಾ sshkey *privkey)
{
	ಯದಿ (st == ರಿಕ್ತ || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ರಿಕ್ತ))
		abort();
	ಯದಿ ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ಸಂರಚನಾ sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, ಪರಿಮಾಣ(*st->pubkeys));
		st->privkeys = (ಸಂರಚನಾ sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, ಪರಿಮಾಣ(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
prepare_ಕೀಲಿಗಳು(ಸಂರಚನಾ shared_state *st)
{
	ಯದಿ (prepare_ಕೀಲಿ(st, ಕೀಲಿ_RSA, 2048) != 0 ||
	    prepare_ಕೀಲಿ(st, ಕೀಲಿ_ECDSA, 256) != 0 ||
	    prepare_ಕೀಲಿ(st, ಕೀಲಿ_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
get_pubkey(ಸಂರಚನಾ shared_state *st, ಪೂರ್ಣಾಙ್ಕ keytype)
{
	ಯದಿ (st == ರಿಕ್ತ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == ರಿಕ್ತ || st->pubkeys[keytype] == ರಿಕ್ತ)
		abort();
	ಪ್ರತ್ಯಾಗಮ st->pubkeys[keytype];
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
get_privkey(ಸಂರಚನಾ shared_state *st, ಪೂರ್ಣಾಙ್ಕ keytype)
{
	ಯದಿ (st == ರಿಕ್ತ || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == ರಿಕ್ತ || st->privkeys[keytype] == ರಿಕ್ತ)
		abort();
	ಪ್ರತ್ಯಾಗಮ st->privkeys[keytype];
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
build_proposal_side(ವರ್ಣ **out, ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX],
    ಧ್ರುವ ವರ್ಣ *kex, ಧ್ರುವ ವರ್ಣ *keyname,
    ಧ್ರುವ ವರ್ಣ *cipher, ಧ್ರುವ ವರ್ಣ *mac, ಧ್ರುವ ವರ್ಣ *comp)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			ccp = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS && kex != ರಿಕ್ತ)
			ccp = kex;
		ಅನ್ಯಥಾ ಯದಿ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ರಿಕ್ತ)
			ccp = cipher;
		ಅನ್ಯಥಾ ಯದಿ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ರಿಕ್ತ)
			ccp = mac;
		ಅನ್ಯಥಾ ಯದಿ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ರಿಕ್ತ)
			ccp = comp;
		ಯದಿ ((out[i] = strdup(ccp)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_kex_with_ಕೀಲಿ(ಸಂರಚನಾ shared_state *st, ಸಂರಚನಾ test_state *ts,
    ಧ್ರುವ ವರ್ಣ *kex, ಪೂರ್ಣಾಙ್ಕ keytype, ಧ್ರುವ ಸಂರಚನಾ kex_overrides *ov)
{
	ಸಂರಚನಾ ssh *client = ರಿಕ್ತ, *server = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *privkey = ರಿಕ್ತ, *pubkey = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *state = ರಿಕ್ತ;
	ಸಂರಚನಾ kex_params kex_params;
	ಧ್ರುವ ವರ್ಣ *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *myproposal[PROPOSAL_MAX] = {0};
	ವರ್ಣ *keyname = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, r;

	ts->cin = ts->sin = ರಿಕ್ತ;
	ಯದಿ (ts->c_template != ರಿಕ್ತ &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == ರಿಕ್ತ)
		abort();
	ಯದಿ (ts->s_template != ರಿಕ್ತ &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == ರಿಕ್ತ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ಯದಿ (ts->cin != ರಿಕ್ತ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} ಅನ್ಯಥಾ ಯದಿ (ts->sin != ರಿಕ್ತ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} ಅನ್ಯಥಾ
		debug_f("%s %s noclobber", kex, keyname);

	ಯದಿ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ರಿಕ್ತ,
	    ov ? ov->mac : ರಿಕ್ತ,
	    ov ? ov->comp : ರಿಕ್ತ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ fail;
	}
	memcpy(kex_params.proposal, myproposal, ಪರಿಮಾಣ(myproposal));
	ಯದಿ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		ಗಚ್ಛ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	ಮುಕ್ತ(keyname);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
prepare_ಕೀಲಿ(ಸಂರಚನಾ shared_state *st, ಪೂರ್ಣಾಙ್ಕ kt, ಪೂರ್ಣಾಙ್ಕ bits)
{
	ಧ್ರುವ ವರ್ಣ *pubstr = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *privstr = ರಿಕ್ತ;
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *privkey = ರಿಕ್ತ, *pubkey = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ವಿಕಲ್ಪ (kt) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		abort();
	}
	ಯದಿ ((b = sshbuf_from(privstr, strlen(privstr))) == ರಿಕ್ತ)
		abort();
	ಯದಿ ((r = sshkey_parse_private_fileblob(b, "", &privkey, ರಿಕ್ತ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ಯದಿ ((pubkey = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		abort();
	ಯದಿ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	ಮುಕ್ತ(tmp);

	store_ಕೀಲಿ(st, pubkey, privkey);
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ಯದಿ defined(STANDALONE)

#ಯದಿ 0 /* use this if generating new keys to embed above */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
prepare_ಕೀಲಿ(ಸಂರಚನಾ shared_state *st, ಪೂರ್ಣಾಙ್ಕ keytype, ಪೂರ್ಣಾಙ್ಕ bits)
{
	ಸಂರಚನಾ sshkey *privkey = ರಿಕ್ತ, *pubkey = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ಯದಿ ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ಕೀಲಿ(st, pubkey, privkey);
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

ಪೂರ್ಣಾಙ್ಕ main(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಸಂರಚನಾ shared_state *st;
	ಸಂರಚನಾ test_state *ts;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ keytypes[] = { ಕೀಲಿ_RSA, ಕೀಲಿ_ECDSA, ಕೀಲಿ_ED25519, -1 };
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ರಿಕ್ತ,
	};
	ಪೂರ್ಣಾಙ್ಕ i, j;
	ವರ್ಣ *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ಯದಿ (st == ರಿಕ್ತ) {
		st = (ಸಂರಚನಾ shared_state *)xcalloc(1, ಪರಿಮಾಣ(*st));
		prepare_ಕೀಲಿಗಳು(st);
	}
	/* Run each kex method for each key and save client/server packets */
	ಪ್ರತಿ (i = 0; keytypes[i] != -1; i++) {
		ಪ್ರತಿ (j = 0; kextypes[j] != ರಿಕ್ತ; j++) {
			ts = (ಸಂರಚನಾ test_state *)xcalloc(1, ಪರಿಮಾಣ(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ಕೀಲಿ(st, ts, kextypes[j], keytypes[i], ರಿಕ್ತ);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ಯದಿ ((f = fopen(path, "wb+")) == ರಿಕ್ತ)
				abort();
			ಯದಿ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			ಮುಕ್ತ(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ಯದಿ ((f = fopen(path, "wb+")) == ರಿಕ್ತ)
				abort();
			ಯದಿ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			ಮುಕ್ತ(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			ಮುಕ್ತ(ts);
		}
	}
	ಪ್ರತಿ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		ಯದಿ (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, ರಿಕ್ತ, 0) != 0)
			abort();
		ಮುಕ್ತ(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		ಯದಿ (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		ಮುಕ್ತ(path);
	}
}
#ಅನ್ಯಥಾ /* !STANDALONE */
ಸ್ಥಿರ ಶೂನ್ಯ
do_kex(ಸಂರಚನಾ shared_state *st, ಸಂರಚನಾ test_state *ts, ಧ್ರುವ ವರ್ಣ *kex)
{
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_RSA, ರಿಕ್ತ);
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ECDSA, ರಿಕ್ತ);
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, ರಿಕ್ತ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
kex_extras(ಸಂರಚನಾ shared_state *st, ಸಂರಚನಾ test_state *ts)
{
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ರಿಕ್ತ,
	};
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ರಿಕ್ತ,
	};
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ comps[] = {
		"zlib@openssh.com",
		"zlib",
		ರಿಕ್ತ,
	};
	ಧ್ರುವ ವರ್ಣ *kex = "curve25519-sha256@libssh.org";
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; ciphers[i] != ರಿಕ್ತ; i++) {
		ಸಂರಚನಾ kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
	ಪ್ರತಿ (i = 0; macs[i] != ರಿಕ್ತ; i++) {
		ಸಂರಚನಾ kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
	ಪ್ರತಿ (i = 0; comps[i] != ರಿಕ್ತ; i++) {
		ಸಂರಚನಾ kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
kex_tests(ಸಂರಚನಾ shared_state *st, ಸಂರಚನಾ test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t* data, size_t size)
{
	ಸ್ಥಿರ ಸಂರಚನಾ shared_state *st;
	ಸಂರಚನಾ test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು * 4];
	u_char zbuf[4096] = {0};
	ಸ್ಥಿರ LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ಯದಿ (st == ರಿಕ್ತ) {
		ಯದಿ (getenv("DEBUG") != ರಿಕ್ತ || getenv("KEX_FUZZ_DEBUG") != ರಿಕ್ತ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ಸಂರಚನಾ shared_state *)xcalloc(1, ಪರಿಮಾಣ(*st));
		prepare_ಕೀಲಿಗಳು(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', ಪರಿಮಾಣ(crbuf));

	ts = (ಸಂರಚನಾ test_state *)xcalloc(1, ಪರಿಮಾಣ(*ts));
	ಯದಿ ((ts->s_template = sshbuf_new()) == ರಿಕ್ತ ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, ಪರಿಮಾಣ(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, ಪರಿಮಾಣ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	ಮುಕ್ತ(ts);

	ts = (ಸಂರಚನಾ test_state *)xcalloc(1, ಪರಿಮಾಣ(*ts));
	ಯದಿ ((ts->c_template = sshbuf_new()) == ರಿಕ್ತ ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, ಪರಿಮಾಣ(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, ಪರಿಮಾಣ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	ಮುಕ್ತ(ts);

	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* STANDALONE */
} /* extern "C" */
