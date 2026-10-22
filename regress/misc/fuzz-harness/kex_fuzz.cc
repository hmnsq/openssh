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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ prepare_ಕೀಲಿ(ರಚನೆ shared_state *st, ಪೂರ್ಣಾಂಕ keytype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು);

ರಚನೆ shared_state {
	ಗಾತ್ರ_t nkeys;
	ರಚನೆ sshkey **privkeys, **pubkeys;
};

ರಚನೆ test_state {
	ರಚನೆ sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ರಚನೆ sshbuf *ಜ್ಯಾ, *ಒಳಗೆ; /* input; setup per-test in do_kex_with_key */
	ರಚನೆ sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ರಚನೆ kex_overrides {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cipher;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *mac;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comp;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_send_and_receive(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ,
    ರಚನೆ sshbuf *store, ಪೂರ್ಣಾಂಕ clobber, ಗಾತ್ರ_t *n)
{
	u_char type;
	ಗಾತ್ರ_t len;
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಪೂರ್ಣಾಂಕ r;

	ಗಾಗಿ (*n = 0;; (*n)++) {
		ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ಹಿಂತಿರುಗಿ r;
		}
		ಆದರೆ (type != 0)
			ಹಿಂತಿರುಗಿ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ಆದರೆ (len == 0)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ಹಿಂತಿರುಗಿ r;
		}
		ಆದರೆ (store != ಖಾಲಿ && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ಹಿಂತಿರುಗಿ r;
		}
		ಆದರೆ (!clobber && (r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ಹಿಂತಿರುಗಿ r;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ test_state *ts, ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r = 0;
	ಗಾತ್ರ_t cn, sn;

	/* If fuzzing, replace server/client input */
	ಆದರೆ (ts->ಜ್ಯಾ != ಖಾಲಿ) {
		ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(server, sshbuf_ptr(ts->ಜ್ಯಾ),
		    sshbuf_len(ts->ಜ್ಯಾ))) != 0) {
			error_fr(r, "ssh_input_append");
			ಹಿಂತಿರುಗಿ r;
		}
		sshbuf_reset(ts->ಜ್ಯಾ);
	}
	ಆದರೆ (ts->ಒಳಗೆ != ಖಾಲಿ) {
		ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(client, sshbuf_ptr(ts->ಒಳಗೆ),
		    sshbuf_len(ts->ಒಳಗೆ))) != 0) {
			error_fr(r, "ssh_input_append");
			ಹಿಂತಿರುಗಿ r;
		}
		sshbuf_reset(ts->ಒಳಗೆ);
	}
	ಆಗ (!server->kex->ಮುಗಿದ || !client->kex->ಮುಗಿದ) {
		cn = sn = 0;
		debug_f("S:");
		ಆದರೆ ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->ಒಳಗೆ != ಖಾಲಿ, &sn)) != 0) {
			debug_fr(r, "S->C");
			ನಿಲ್ಲಿಸು;
		}
		debug_f("C:");
		ಆದರೆ ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->ಜ್ಯಾ != ಖಾಲಿ, &cn)) != 0) {
			debug_fr(r, "C->S");
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ನಿಲ್ಲಿಸು;
		}
	}
	debug_fr(r, "done");
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
store_ಕೀಲಿ(ರಚನೆ shared_state *st, ರಚನೆ sshkey *pubkey,
    ರಚನೆ sshkey *privkey)
{
	ಆದರೆ (st == ಖಾಲಿ || pubkey->type < 0 || pubkey->type > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ ||
	    privkey->type != pubkey->type ||
	    ((ಗಾತ್ರ_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ಖಾಲಿ))
		abort();
	ಆದರೆ ((ಗಾತ್ರ_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ರಚನೆ sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, ಗಾತ್ರ(*st->pubkeys));
		st->privkeys = (ರಚನೆ sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, ಗಾತ್ರ(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
prepare_ಕೀಲಿಗಳು(ರಚನೆ shared_state *st)
{
	ಆದರೆ (prepare_ಕೀಲಿ(st, ಕೀಲಿ_RSA, 2048) != 0 ||
	    prepare_ಕೀಲಿ(st, ಕೀಲಿ_ECDSA, 256) != 0 ||
	    prepare_ಕೀಲಿ(st, ಕೀಲಿ_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
get_pubkey(ರಚನೆ shared_state *st, ಪೂರ್ಣಾಂಕ keytype)
{
	ಆದರೆ (st == ಖಾಲಿ || keytype < 0 || (ಗಾತ್ರ_t)keytype >= st->nkeys ||
	    st->pubkeys == ಖಾಲಿ || st->pubkeys[keytype] == ಖಾಲಿ)
		abort();
	ಹಿಂತಿರುಗಿ st->pubkeys[keytype];
}

ಸ್ಥಿರ ರಚನೆ sshkey *
get_privkey(ರಚನೆ shared_state *st, ಪೂರ್ಣಾಂಕ keytype)
{
	ಆದರೆ (st == ಖಾಲಿ || keytype < 0 || (ಗಾತ್ರ_t)keytype >= st->nkeys ||
	    st->privkeys == ಖಾಲಿ || st->privkeys[keytype] == ಖಾಲಿ)
		abort();
	ಹಿಂತಿರುಗಿ st->privkeys[keytype];
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
build_proposal_side(ಅಕ್ಷರ **ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX],
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kex, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *keyname,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cipher, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *mac, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comp)
{
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ccp = defaults[i];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CIPHER_NONE_AVAIL
		ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			ccp = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS && kex != ಖಾಲಿ)
			ccp = kex;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ಖಾಲಿ)
			ccp = cipher;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ಖಾಲಿ)
			ccp = mac;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ಖಾಲಿ)
			ccp = comp;
		ಆದರೆ ((ಹೊರಹೋಗು[i] = strdup(ccp)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_kex_with_ಕೀಲಿ(ರಚನೆ shared_state *st, ರಚನೆ test_state *ts,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kex, ಪೂರ್ಣಾಂಕ keytype, ಸ್ಥಿರಾಂಕ ರಚನೆ kex_overrides *ov)
{
	ರಚನೆ ssh *client = ಖಾಲಿ, *server = ಖಾಲಿ;
	ರಚನೆ sshkey *privkey = ಖಾಲಿ, *pubkey = ಖಾಲಿ;
	ರಚನೆ sshbuf *state = ಖಾಲಿ;
	ರಚನೆ kex_params kex_params;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *myproposal[PROPOSAL_MAX] = {0};
	ಅಕ್ಷರ *keyname = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, r;

	ts->ಒಳಗೆ = ts->ಜ್ಯಾ = ಖಾಲಿ;
	ಆದರೆ (ts->c_template != ಖಾಲಿ &&
	    (ts->ಒಳಗೆ = sshbuf_fromb(ts->c_template)) == ಖಾಲಿ)
		abort();
	ಆದರೆ (ts->s_template != ಖಾಲಿ &&
	    (ts->ಜ್ಯಾ = sshbuf_fromb(ts->s_template)) == ಖಾಲಿ)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ಆದರೆ (ts->ಒಳಗೆ != ಖಾಲಿ) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->ಒಳಗೆ));
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ts->ಜ್ಯಾ != ಖಾಲಿ) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->ಜ್ಯಾ));
	} ಇಲ್ಲದಿದ್ದರೆ
		debug_f("%s %s noclobber", kex, keyname);

	ಆದರೆ (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ಖಾಲಿ,
	    ov ? ov->mac : ಖಾಲಿ,
	    ov ? ov->comp : ಖಾಲಿ) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು fail;
	}
	ಸ್ಮರಣೆ_ನಕಲು(kex_params.proposal, myproposal, ಗಾತ್ರ(myproposal));
	ಆದರೆ ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = ssh_ಕೂಡಿಸು_hostkey(server, privkey)) != 0 ||
	    (r = ssh_ಕೂಡಿಸು_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = ಸತತ_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		ಹೋಗು fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(myproposal[i]);
	sshbuf_free(ts->ಜ್ಯಾ);
	sshbuf_free(ts->ಒಳಗೆ);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	ಬಿಡುಗಡೆ(keyname);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
prepare_ಕೀಲಿ(ರಚನೆ shared_state *st, ಪೂರ್ಣಾಂಕ kt, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pubstr = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *privstr = ಖಾಲಿ;
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *privkey = ಖಾಲಿ, *pubkey = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆಯ್ಕೆ (kt) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}
	ಆದರೆ ((b = sshbuf_from(privstr, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(privstr))) == ಖಾಲಿ)
		abort();
	ಆದರೆ ((r = sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &privkey, ಖಾಲಿ)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ಆದರೆ ((pubkey = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		abort();
	ಆದರೆ ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	ಬಿಡುಗಡೆ(tmp);

	store_ಕೀಲಿ(st, pubkey, privkey);
	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ defined(STANDALONE)

#ಆದರೆ 0 /* use this if generating new keys to embed above */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
prepare_ಕೀಲಿ(ರಚನೆ shared_state *st, ಪೂರ್ಣಾಂಕ keytype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ರಚನೆ sshkey *privkey = ಖಾಲಿ, *pubkey = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_generate(keytype, ಬಿಟ್ಟುಗಳು, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ಕೀಲಿ(st, pubkey, privkey);
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ ಮುಖ್ಯ(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ರಚನೆ shared_state *st;
	ರಚನೆ test_state *ts;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ keytypes[] = { ಕೀಲಿ_RSA, ಕೀಲಿ_ECDSA, ಕೀಲಿ_ED25519, -1 };
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ಖಾಲಿ,
	};
	ಪೂರ್ಣಾಂಕ i, j;
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ಆದರೆ (st == ಖಾಲಿ) {
		st = (ರಚನೆ shared_state *)xcalloc(1, ಗಾತ್ರ(*st));
		prepare_ಕೀಲಿಗಳು(st);
	}
	/* Run each kex method for each key and save client/server packets */
	ಗಾಗಿ (i = 0; keytypes[i] != -1; i++) {
		ಗಾಗಿ (j = 0; kextypes[j] != ಖಾಲಿ; j++) {
			ts = (ರಚನೆ test_state *)xcalloc(1, ಗಾತ್ರ(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ಕೀಲಿ(st, ts, kextypes[j], keytypes[i], ಖಾಲಿ);
			xasprintf(&ಮಾರ್ಗ, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", ಮಾರ್ಗ);
			ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "wb+")) == ಖಾಲಿ)
				abort();
			ಆದರೆ (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&ಮಾರ್ಗ, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", ಮಾರ್ಗ);
			ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "wb+")) == ಖಾಲಿ)
				abort();
			ಆದರೆ (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			ಬಿಡುಗಡೆ(ts);
		}
	}
	ಗಾಗಿ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&ಮಾರ್ಗ, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", ಮಾರ್ಗ);
		ಆದರೆ (sshkey_save_ಖಾಸಗಿ(st->privkeys[keytypes[i]], ಮಾರ್ಗ,
		    "", "", SSHKEY_ಖಾಸಗಿ_OPENSSH, ಖಾಲಿ, 0) != 0)
			abort();
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
		xasprintf(&ಮಾರ್ಗ, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", ಮಾರ್ಗ);
		ಆದರೆ (sshkey_save_ಬಹಿರಂಗ(st->pubkeys[keytypes[i]], ಮಾರ್ಗ, "") != 0)
			abort();
		ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	}
}
#ಇಲ್ಲದಿದ್ದರೆ /* !STANDALONE */
ಸ್ಥಿರ ಶೂನ್ಯ
do_kex(ರಚನೆ shared_state *st, ರಚನೆ test_state *ts, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kex)
{
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_RSA, ಖಾಲಿ);
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ECDSA, ಖಾಲಿ);
	do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, ಖಾಲಿ);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
kex_extras(ರಚನೆ shared_state *st, ರಚನೆ test_state *ts)
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ಖಾಲಿ,
	};
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ಖಾಲಿ,
	};
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ comps[] = {
		"zlib@openssh.com",
		"zlib",
		ಖಾಲಿ,
	};
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *kex = "curve25519-sha256@libssh.org";
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; ciphers[i] != ಖಾಲಿ; i++) {
		ರಚನೆ kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
	ಗಾಗಿ (i = 0; macs[i] != ಖಾಲಿ; i++) {
		ರಚನೆ kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
	ಗಾಗಿ (i = 0; comps[i] != ಖಾಲಿ; i++) {
		ರಚನೆ kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ಕೀಲಿ(st, ts, kex, ಕೀಲಿ_ED25519, &ov);
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
kex_tests(ರಚನೆ shared_state *st, ರಚನೆ test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

ಪೂರ್ಣಾಂಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t* ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಸ್ಥಿರ ರಚನೆ shared_state *st;
	ರಚನೆ test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು * 4];
	u_char zbuf[4096] = {0};
	ಸ್ಥಿರ LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ಆದರೆ (st == ಖಾಲಿ) {
		ಆದರೆ (getenv("DEBUG") != ಖಾಲಿ || getenv("KEX_FUZZ_DEBUG") != ಖಾಲಿ)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ರಚನೆ shared_state *)xcalloc(1, ಗಾತ್ರ(*st));
		prepare_ಕೀಲಿಗಳು(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', ಗಾತ್ರ(crbuf));

	ts = (ರಚನೆ test_state *)xcalloc(1, ಗಾತ್ರ(*ts));
	ಆದರೆ ((ts->s_template = sshbuf_new()) == ಖಾಲಿ ||
	    sshbuf_put(ts->s_template, ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, ಗಾತ್ರ(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, ಗಾತ್ರ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	ಬಿಡುಗಡೆ(ts);

	ts = (ರಚನೆ test_state *)xcalloc(1, ಗಾತ್ರ(*ts));
	ಆದರೆ ((ts->c_template = sshbuf_new()) == ಖಾಲಿ ||
	    sshbuf_put(ts->c_template, ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, ಗಾತ್ರ(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, ಗಾತ್ರ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	ಬಿಡುಗಡೆ(ts);

	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* STANDALONE */
} /* extern "C" */
