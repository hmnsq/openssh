// libfuzzer driver for key exchange fuzzing.


#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା prepare_ଚାବି(ସଂରଚନା shared_state *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits);

ସଂରଚନା shared_state {
	size_t nkeys;
	ସଂରଚନା sshkey **privkeys, **pubkeys;
};

ସଂରଚନା test_state {
	ସଂରଚନା sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	ସଂରଚନା sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	ସଂରଚନା sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
ସଂରଚନା kex_overrides {
	ଅଚଳ ଅକ୍ଷର *cipher;
	ଅଚଳ ଅକ୍ଷର *mac;
	ଅଚଳ ଅକ୍ଷର *comp;
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_send_and_receive(ସଂରଚନା ssh *from, ସଂରଚନା ssh *to,
    ସଂରଚନା sshbuf *store, ପୂର୍ଣ୍ଣସଂଖ୍ୟା clobber, size_t *n)
{
	u_char type;
	size_t len;
	ଅଚଳ u_char *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ପାଇଁ (*n = 0;; (*n)++) {
		ଯଦି ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ଫେରନ୍ତୁ r;
		}
		ଯଦି (type != 0)
			ଫେରନ୍ତୁ 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		ଯଦି (len == 0)
			ଫେରନ୍ତୁ 0;
		ଯଦି ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ଫେରନ୍ତୁ r;
		}
		ଯଦି (store != ଖାଲି && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ଫେରନ୍ତୁ r;
		}
		ଯଦି (!clobber && (r = ssh_ନିବେଶ_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ଫେରନ୍ତୁ r;
		}
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
run_kex(ସଂରଚନା test_state *ts, ସଂରଚନା ssh *client, ସଂରଚନା ssh *server)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	ଯଦି (ts->sin != ଖାଲି) {
		ଯଦି ((r = ssh_ନିବେଶ_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ଫେରନ୍ତୁ r;
		}
		sshbuf_reset(ts->sin);
	}
	ଯଦି (ts->cin != ଖାଲି) {
		ଯଦି ((r = ssh_ନିବେଶ_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ଫେରନ୍ତୁ r;
		}
		sshbuf_reset(ts->cin);
	}
	ଯେତେବେଳେ (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		ଯଦି ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != ଖାଲି, &sn)) != 0) {
			debug_fr(r, "S->C");
			ଭାଙ୍ଗ;
		}
		debug_f("C:");
		ଯଦି ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != ଖାଲି, &cn)) != 0) {
			debug_fr(r, "C->S");
			ଭାଙ୍ଗ;
		}
		ଯଦି (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ଭାଙ୍ଗ;
		}
	}
	debug_fr(r, "done");
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
store_ଚାବି(ସଂରଚନା shared_state *st, ସଂରଚନା sshkey *pubkey,
    ସଂରଚନା sshkey *privkey)
{
	ଯଦି (st == ଖାଲି || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != ଖାଲି))
		abort();
	ଯଦି ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (ସଂରଚନା sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, ଆକାର(*st->pubkeys));
		st->privkeys = (ସଂରଚନା sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, ଆକାର(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
prepare_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା shared_state *st)
{
	ଯଦି (prepare_ଚାବି(st, ଚାବି_RSA, 2048) != 0 ||
	    prepare_ଚାବି(st, ଚାବି_ECDSA, 256) != 0 ||
	    prepare_ଚାବି(st, ଚାବି_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା sshkey *
get_pubkey(ସଂରଚନା shared_state *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype)
{
	ଯଦି (st == ଖାଲି || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == ଖାଲି || st->pubkeys[keytype] == ଖାଲି)
		abort();
	ଫେରନ୍ତୁ st->pubkeys[keytype];
}

ସ୍ଥିର ସଂରଚନା sshkey *
get_privkey(ସଂରଚନା shared_state *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype)
{
	ଯଦି (st == ଖାଲି || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == ଖାଲି || st->privkeys[keytype] == ଖାଲି)
		abort();
	ଫେରନ୍ତୁ st->privkeys[keytype];
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
build_proposal_side(ଅକ୍ଷର **out, ଅଚଳ ଅକ୍ଷର *defaults[PROPOSAL_MAX],
    ଅଚଳ ଅକ୍ଷର *kex, ଅଚଳ ଅକ୍ଷର *keyname,
    ଅଚଳ ଅକ୍ଷର *cipher, ଅଚଳ ଅକ୍ଷର *mac, ଅଚଳ ଅକ୍ଷର *comp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଅଚଳ ଅକ୍ଷର *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		ଯଦି (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		ଯଦି (i == PROPOSAL_SERVER_HOST_ଚାବି_ALGS)
			ccp = keyname;
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_KEX_ALGS && kex != ଖାଲି)
			ccp = kex;
		ଅନ୍ୟଥା ଯଦି ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != ଖାଲି)
			ccp = cipher;
		ଅନ୍ୟଥା ଯଦି ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != ଖାଲି)
			ccp = mac;
		ଅନ୍ୟଥା ଯଦି ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != ଖାଲି)
			ccp = comp;
		ଯଦି ((out[i] = strdup(ccp)) == ଖାଲି)
			ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_kex_with_ଚାବି(ସଂରଚନା shared_state *st, ସଂରଚନା test_state *ts,
    ଅଚଳ ଅକ୍ଷର *kex, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ଅଚଳ ସଂରଚନା kex_overrides *ov)
{
	ସଂରଚନା ssh *client = ଖାଲି, *server = ଖାଲି;
	ସଂରଚନା sshkey *privkey = ଖାଲି, *pubkey = ଖାଲି;
	ସଂରଚନା sshbuf *state = ଖାଲି;
	ସଂରଚନା kex_params kex_params;
	ଅଚଳ ଅକ୍ଷର *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *myproposal[PROPOSAL_MAX] = {0};
	ଅକ୍ଷର *keyname = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;

	ts->cin = ts->sin = ଖାଲି;
	ଯଦି (ts->c_template != ଖାଲି &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == ଖାଲି)
		abort();
	ଯଦି (ts->s_template != ଖାଲି &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == ଖାଲି)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	ଯଦି (ts->cin != ଖାଲି) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} ଅନ୍ୟଥା ଯଦି (ts->sin != ଖାଲି) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} ଅନ୍ୟଥା
		debug_f("%s %s noclobber", kex, keyname);

	ଯଦି (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : ଖାଲି,
	    ov ? ov->mac : ଖାଲି,
	    ov ? ov->comp : ଖାଲି) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ fail;
	}
	memcpy(kex_params.proposal, myproposal, ଆକାର(myproposal));
	ଯଦି ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		ଯାଅ fail;
	}
	ଯଦି ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		ଯାଅ fail;
	}
	ଯଦି ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		ଯାଅ fail;
	}
	ଯଦି ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		ଯାଅ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	ମୁକ୍ତ(keyname);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
prepare_ଚାବି(ସଂରଚନା shared_state *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା kt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ଅଚଳ ଅକ୍ଷର *pubstr = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *privstr = ଖାଲି;
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *privkey = ଖାଲି, *pubkey = ଖାଲି;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ବାଛ (kt) {
	ସ୍ଥିତି ଚାବି_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}
	ଯଦି ((b = sshbuf_from(privstr, strlen(privstr))) == ଖାଲି)
		abort();
	ଯଦି ((r = sshkey_parse_private_fileblob(b, "", &privkey, ଖାଲି)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	ଯଦି ((pubkey = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		abort();
	ଯଦି ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	ମୁକ୍ତ(tmp);

	store_ଚାବି(st, pubkey, privkey);
	ଫେରନ୍ତୁ 0;
}

#ଯଦି defined(STANDALONE)

#ଯଦି 0 /* use this if generating new keys to embed above */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
prepare_ଚାବି(ସଂରଚନା shared_state *st, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ସଂରଚନା sshkey *privkey = ଖାଲି, *pubkey = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	ଯଦି ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_ଚାବି(st, pubkey, privkey);
	ଫେରନ୍ତୁ 0;
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୁଖ୍ୟ(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ସଂରଚନା shared_state *st;
	ସଂରଚନା test_state *ts;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytypes[] = { ଚାବି_RSA, ଚାବି_ECDSA, ଚାବି_ED25519, -1 };
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		ଖାଲି,
	};
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;
	ଅକ୍ଷର *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	ଯଦି (st == ଖାଲି) {
		st = (ସଂରଚନା shared_state *)xcalloc(1, ଆକାର(*st));
		prepare_ଚାବିଗୁଡ଼ିକ(st);
	}
	/* Run each kex method for each key and save client/server packets */
	ପାଇଁ (i = 0; keytypes[i] != -1; i++) {
		ପାଇଁ (j = 0; kextypes[j] != ଖାଲି; j++) {
			ts = (ସଂରଚନା test_state *)xcalloc(1, ଆକାର(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_ଚାବି(st, ts, kextypes[j], keytypes[i], ଖାଲି);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ଯଦି ((f = fopen(path, "wb+")) == ଖାଲି)
				abort();
			ଯଦି (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			ମୁକ୍ତ(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			ଯଦି ((f = fopen(path, "wb+")) == ଖାଲି)
				abort();
			ଯଦି (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			ମୁକ୍ତ(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			ମୁକ୍ତ(ts);
		}
	}
	ପାଇଁ (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		ଯଦି (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, ଖାଲି, 0) != 0)
			abort();
		ମୁକ୍ତ(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		ଯଦି (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		ମୁକ୍ତ(path);
	}
}
#ଅନ୍ୟଥା /* !STANDALONE */
ସ୍ଥିର ଶୂନ୍ୟ
do_kex(ସଂରଚନା shared_state *st, ସଂରଚନା test_state *ts, ଅଚଳ ଅକ୍ଷର *kex)
{
	do_kex_with_ଚାବି(st, ts, kex, ଚାବି_RSA, ଖାଲି);
	do_kex_with_ଚାବି(st, ts, kex, ଚାବି_ECDSA, ଖାଲି);
	do_kex_with_ଚାବି(st, ts, kex, ଚାବି_ED25519, ଖାଲି);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
ସ୍ଥିର ଶୂନ୍ୟ
kex_extras(ସଂରଚନା shared_state *st, ସଂରଚନା test_state *ts)
{
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		ଖାଲି,
	};
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		ଖାଲି,
	};
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର * ଅଚଳ comps[] = {
		"zlib@openssh.com",
		"zlib",
		ଖାଲି,
	};
	ଅଚଳ ଅକ୍ଷର *kex = "curve25519-sha256@libssh.org";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; ciphers[i] != ଖାଲି; i++) {
		ସଂରଚନା kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_ଚାବି(st, ts, kex, ଚାବି_ED25519, &ov);
	}
	ପାଇଁ (i = 0; macs[i] != ଖାଲି; i++) {
		ସଂରଚନା kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_ଚାବି(st, ts, kex, ଚାବି_ED25519, &ov);
	}
	ପାଇଁ (i = 0; comps[i] != ଖାଲି; i++) {
		ସଂରଚନା kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_ଚାବି(st, ts, kex, ଚାବି_ED25519, &ov);
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
kex_tests(ସଂରଚନା shared_state *st, ସଂରଚନା test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* data, size_t size)
{
	ସ୍ଥିର ସଂରଚନା shared_state *st;
	ସଂରଚନା test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_ଧାଡ଼ିଗୁଡ଼ିକ * 4];
	u_char zbuf[4096] = {0};
	ସ୍ଥିର LogLevel loglevel = SYSLOG_LEVEL_INFO;

	ଯଦି (st == ଖାଲି) {
		ଯଦି (getenv("DEBUG") != ଖାଲି || getenv("KEX_FUZZ_DEBUG") != ଖାଲି)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (ସଂରଚନା shared_state *)xcalloc(1, ଆକାର(*st));
		prepare_ଚାବିଗୁଡ଼ିକ(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', ଆକାର(crbuf));

	ts = (ସଂରଚନା test_state *)xcalloc(1, ଆକାର(*ts));
	ଯଦି ((ts->s_template = sshbuf_new()) == ଖାଲି ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, ଆକାର(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, ଆକାର(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	ମୁକ୍ତ(ts);

	ts = (ସଂରଚନା test_state *)xcalloc(1, ଆକାର(*ts));
	ଯଦି ((ts->c_template = sshbuf_new()) == ଖାଲି ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, ଆକାର(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, ଆକାର(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	ମୁକ୍ତ(ts);

	ଫେରନ୍ତୁ 0;
}
#endif /* STANDALONE */
} /* extern "C" */
