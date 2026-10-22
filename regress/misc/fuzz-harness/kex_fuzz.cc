// libfuzzer driver for key exchange fuzzing.


#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி "C" {

#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "log.h"

#அந்தர்பாவ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

நிலையான முழு prepare_சாவி(கட்டமைப்பு shared_state *st, முழு keytype, முழு bits);

கட்டமைப்பு shared_state {
	size_t nkeys;
	கட்டமைப்பு sshkey **privkeys, **pubkeys;
};

கட்டமைப்பு test_state {
	கட்டமைப்பு sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	கட்டமைப்பு sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	கட்டமைப்பு sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
கட்டமைப்பு kex_overrides {
	மாறிலி எழுத்து *cipher;
	மாறிலி எழுத்து *mac;
	மாறிலி எழுத்து *comp;
};

நிலையான முழு
do_send_and_receive(கட்டமைப்பு ssh *from, கட்டமைப்பு ssh *to,
    கட்டமைப்பு sshbuf *store, முழு clobber, size_t *n)
{
	u_char type;
	size_t len;
	மாறிலி u_char *buf;
	முழு r;

	க்கு (*n = 0;; (*n)++) {
		எனில் ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			திரும்பு r;
		}
		எனில் (type != 0)
			திரும்பு 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		எனில் (len == 0)
			திரும்பு 0;
		எனில் ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			திரும்பு r;
		}
		எனில் (store != வெற்று && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			திரும்பு r;
		}
		எனில் (!clobber && (r = ssh_உள்ளீடு_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			திரும்பு r;
		}
	}
}

நிலையான முழு
run_kex(கட்டமைப்பு test_state *ts, கட்டமைப்பு ssh *client, கட்டமைப்பு ssh *server)
{
	முழு r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	எனில் (ts->sin != வெற்று) {
		எனில் ((r = ssh_உள்ளீடு_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			திரும்பு r;
		}
		sshbuf_reset(ts->sin);
	}
	எனில் (ts->cin != வெற்று) {
		எனில் ((r = ssh_உள்ளீடு_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			திரும்பு r;
		}
		sshbuf_reset(ts->cin);
	}
	போது (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		எனில் ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != வெற்று, &sn)) != 0) {
			debug_fr(r, "S->C");
			நிறுத்து;
		}
		debug_f("C:");
		எனில் ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != வெற்று, &cn)) != 0) {
			debug_fr(r, "C->S");
			நிறுத்து;
		}
		எனில் (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			நிறுத்து;
		}
	}
	debug_fr(r, "done");
	திரும்பு r;
}

நிலையான வெறுமை
store_சாவி(கட்டமைப்பு shared_state *st, கட்டமைப்பு sshkey *pubkey,
    கட்டமைப்பு sshkey *privkey)
{
	எனில் (st == வெற்று || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != வெற்று))
		abort();
	எனில் ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (கட்டமைப்பு sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, அளவு(*st->pubkeys));
		st->privkeys = (கட்டமைப்பு sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, அளவு(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

நிலையான முழு
prepare_சாவிகள்(கட்டமைப்பு shared_state *st)
{
	எனில் (prepare_சாவி(st, சாவி_RSA, 2048) != 0 ||
	    prepare_சாவி(st, சாவி_ECDSA, 256) != 0 ||
	    prepare_சாவி(st, சாவி_ED25519, 256) != 0) {
		error_f("key prepare failed");
		திரும்பு -1;
	}
	திரும்பு 0;
}

நிலையான கட்டமைப்பு sshkey *
get_pubkey(கட்டமைப்பு shared_state *st, முழு keytype)
{
	எனில் (st == வெற்று || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == வெற்று || st->pubkeys[keytype] == வெற்று)
		abort();
	திரும்பு st->pubkeys[keytype];
}

நிலையான கட்டமைப்பு sshkey *
get_privkey(கட்டமைப்பு shared_state *st, முழு keytype)
{
	எனில் (st == வெற்று || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == வெற்று || st->privkeys[keytype] == வெற்று)
		abort();
	திரும்பு st->privkeys[keytype];
}

நிலையான முழு
build_proposal_side(எழுத்து **out, மாறிலி எழுத்து *defaults[PROPOSAL_MAX],
    மாறிலி எழுத்து *kex, மாறிலி எழுத்து *keyname,
    மாறிலி எழுத்து *cipher, மாறிலி எழுத்து *mac, மாறிலி எழுத்து *comp)
{
	முழு i;
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		மாறிலி எழுத்து *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		எனில் (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		எனில் (i == PROPOSAL_SERVER_HOST_சாவி_ALGS)
			ccp = keyname;
		இல்லையெனில் எனில் (i == PROPOSAL_KEX_ALGS && kex != வெற்று)
			ccp = kex;
		இல்லையெனில் எனில் ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != வெற்று)
			ccp = cipher;
		இல்லையெனில் எனில் ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != வெற்று)
			ccp = mac;
		இல்லையெனில் எனில் ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != வெற்று)
			ccp = comp;
		எனில் ((out[i] = strdup(ccp)) == வெற்று)
			திரும்பு -1;
	}
	திரும்பு 0;
}

நிலையான முழு
do_kex_with_சாவி(கட்டமைப்பு shared_state *st, கட்டமைப்பு test_state *ts,
    மாறிலி எழுத்து *kex, முழு keytype, மாறிலி கட்டமைப்பு kex_overrides *ov)
{
	கட்டமைப்பு ssh *client = வெற்று, *server = வெற்று;
	கட்டமைப்பு sshkey *privkey = வெற்று, *pubkey = வெற்று;
	கட்டமைப்பு sshbuf *state = வெற்று;
	கட்டமைப்பு kex_params kex_params;
	மாறிலி எழுத்து *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *myproposal[PROPOSAL_MAX] = {0};
	எழுத்து *keyname = வெற்று;
	முழு i, r;

	ts->cin = ts->sin = வெற்று;
	எனில் (ts->c_template != வெற்று &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == வெற்று)
		abort();
	எனில் (ts->s_template != வெற்று &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == வெற்று)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	எனில் (ts->cin != வெற்று) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} இல்லையெனில் எனில் (ts->sin != வெற்று) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} இல்லையெனில்
		debug_f("%s %s noclobber", kex, keyname);

	எனில் (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : வெற்று,
	    ov ? ov->mac : வெற்று,
	    ov ? ov->comp : வெற்று) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		செல் fail;
	}
	memcpy(kex_params.proposal, myproposal, அளவு(myproposal));
	எனில் ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		செல் fail;
	}
	எனில் ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		செல் fail;
	}
	எனில் ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		செல் fail;
	}
	எனில் ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		செல் fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	விடுவி(keyname);
	திரும்பு r;
}

நிலையான முழு
prepare_சாவி(கட்டமைப்பு shared_state *st, முழு kt, முழு bits)
{
	மாறிலி எழுத்து *pubstr = வெற்று;
	மாறிலி எழுத்து *privstr = வெற்று;
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *privkey = வெற்று, *pubkey = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r;

	தேர்வு (kt) {
	நிலை சாவி_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		நிறுத்து;
	நிலை சாவி_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		நிறுத்து;
	நிலை சாவி_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		நிறுத்து;
	இயல்பு:
		abort();
	}
	எனில் ((b = sshbuf_from(privstr, strlen(privstr))) == வெற்று)
		abort();
	எனில் ((r = sshkey_parse_private_fileblob(b, "", &privkey, வெற்று)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	எனில் ((pubkey = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		abort();
	எனில் ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	விடுவி(tmp);

	store_சாவி(st, pubkey, privkey);
	திரும்பு 0;
}

#எனில் defined(STANDALONE)

#எனில் 0 /* use this if generating new keys to embed above */
நிலையான முழு
prepare_சாவி(கட்டமைப்பு shared_state *st, முழு keytype, முழு bits)
{
	கட்டமைப்பு sshkey *privkey = வெற்று, *pubkey = வெற்று;
	முழு r;

	எனில் ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	எனில் ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_சாவி(st, pubkey, privkey);
	திரும்பு 0;
}
#endif

முழு முதன்மை(வெறுமை)
{
	நிலையான கட்டமைப்பு shared_state *st;
	கட்டமைப்பு test_state *ts;
	மாறிலி முழு keytypes[] = { சாவி_RSA, சாவி_ECDSA, சாவி_ED25519, -1 };
	நிலையான மாறிலி எழுத்து * மாறிலி kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		வெற்று,
	};
	முழு i, j;
	எழுத்து *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	எனில் (st == வெற்று) {
		st = (கட்டமைப்பு shared_state *)xcalloc(1, அளவு(*st));
		prepare_சாவிகள்(st);
	}
	/* Run each kex method for each key and save client/server packets */
	க்கு (i = 0; keytypes[i] != -1; i++) {
		க்கு (j = 0; kextypes[j] != வெற்று; j++) {
			ts = (கட்டமைப்பு test_state *)xcalloc(1, அளவு(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_சாவி(st, ts, kextypes[j], keytypes[i], வெற்று);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			எனில் ((f = fopen(path, "wb+")) == வெற்று)
				abort();
			எனில் (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			விடுவி(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			எனில் ((f = fopen(path, "wb+")) == வெற்று)
				abort();
			எனில் (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			விடுவி(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			விடுவி(ts);
		}
	}
	க்கு (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		எனில் (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, வெற்று, 0) != 0)
			abort();
		விடுவி(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		எனில் (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		விடுவி(path);
	}
}
#இல்லையெனில் /* !STANDALONE */
நிலையான வெறுமை
do_kex(கட்டமைப்பு shared_state *st, கட்டமைப்பு test_state *ts, மாறிலி எழுத்து *kex)
{
	do_kex_with_சாவி(st, ts, kex, சாவி_RSA, வெற்று);
	do_kex_with_சாவி(st, ts, kex, சாவி_ECDSA, வெற்று);
	do_kex_with_சாவி(st, ts, kex, சாவி_ED25519, வெற்று);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
நிலையான வெறுமை
kex_extras(கட்டமைப்பு shared_state *st, கட்டமைப்பு test_state *ts)
{
	நிலையான மாறிலி எழுத்து * மாறிலி ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		வெற்று,
	};
	நிலையான மாறிலி எழுத்து * மாறிலி macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		வெற்று,
	};
	நிலையான மாறிலி எழுத்து * மாறிலி comps[] = {
		"zlib@openssh.com",
		"zlib",
		வெற்று,
	};
	மாறிலி எழுத்து *kex = "curve25519-sha256@libssh.org";
	முழு i;

	க்கு (i = 0; ciphers[i] != வெற்று; i++) {
		கட்டமைப்பு kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_சாவி(st, ts, kex, சாவி_ED25519, &ov);
	}
	க்கு (i = 0; macs[i] != வெற்று; i++) {
		கட்டமைப்பு kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_சாவி(st, ts, kex, சாவி_ED25519, &ov);
	}
	க்கு (i = 0; comps[i] != வெற்று; i++) {
		கட்டமைப்பு kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_சாவி(st, ts, kex, சாவி_ED25519, &ov);
	}
}

நிலையான வெறுமை
kex_tests(கட்டமைப்பு shared_state *st, கட்டமைப்பு test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t* data, size_t size)
{
	நிலையான கட்டமைப்பு shared_state *st;
	கட்டமைப்பு test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_வரிகள் * 4];
	u_char zbuf[4096] = {0};
	நிலையான LogLevel loglevel = SYSLOG_LEVEL_INFO;

	எனில் (st == வெற்று) {
		எனில் (getenv("DEBUG") != வெற்று || getenv("KEX_FUZZ_DEBUG") != வெற்று)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (கட்டமைப்பு shared_state *)xcalloc(1, அளவு(*st));
		prepare_சாவிகள்(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', அளவு(crbuf));

	ts = (கட்டமைப்பு test_state *)xcalloc(1, அளவு(*ts));
	எனில் ((ts->s_template = sshbuf_new()) == வெற்று ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, அளவு(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, அளவு(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	விடுவி(ts);

	ts = (கட்டமைப்பு test_state *)xcalloc(1, அளவு(*ts));
	எனில் ((ts->c_template = sshbuf_new()) == வெற்று ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, அளவு(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, அளவு(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	விடுவி(ts);

	திரும்பு 0;
}
#endif /* STANDALONE */
} /* extern "C" */
