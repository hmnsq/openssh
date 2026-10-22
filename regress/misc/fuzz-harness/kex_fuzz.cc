// libfuzzer driver for key exchange fuzzing.


#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

বাহ্য "C" {

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "ssh_api.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "myproposal.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "log.h"

#অন্তর্ভাৱ "fixed-keys.h"

// Define if you want to generate traces.
/* #define STANDALONE 1 */

স্থির পূর্ণাঙ্ক prepare_চাবি(সংরচনা shared_state *st, পূর্ণাঙ্ক keytype, পূর্ণাঙ্ক bits);

সংরচনা shared_state {
	size_t nkeys;
	সংরচনা sshkey **privkeys, **pubkeys;
};

সংরচনা test_state {
	সংরচনা sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	সংরচনা sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	সংরচনা sshbuf *s_template, *c_template; /* main copy of input */
};

/*
 * Optional proposal overrides applied to both sides. Each field
 * replaces one KEXINIT slot when non-NULL.
 */
সংরচনা kex_overrides {
	ধ্রুৱ ৱর্ণ *cipher;
	ধ্রুৱ ৱর্ণ *mac;
	ধ্রুৱ ৱর্ণ *comp;
};

স্থির পূর্ণাঙ্ক
do_send_and_receive(সংরচনা ssh *from, সংরচনা ssh *to,
    সংরচনা sshbuf *store, পূর্ণাঙ্ক clobber, size_t *n)
{
	u_char type;
	size_t len;
	ধ্রুৱ u_char *buf;
	পূর্ণাঙ্ক r;

	বাবে (*n = 0;; (*n)++) {
		যদি ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			ঘূৰাই r;
		}
		যদি (type != 0)
			ঘূৰাই 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		যদি (len == 0)
			ঘূৰাই 0;
		যদি ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			ঘূৰাই r;
		}
		যদি (store != রিক্ত && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			ঘূৰাই r;
		}
		যদি (!clobber && (r = ssh_প্ৰবেশ_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			ঘূৰাই r;
		}
	}
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা test_state *ts, সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	যদি (ts->sin != রিক্ত) {
		যদি ((r = ssh_প্ৰবেশ_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			ঘূৰাই r;
		}
		sshbuf_reset(ts->sin);
	}
	যদি (ts->cin != রিক্ত) {
		যদি ((r = ssh_প্ৰবেশ_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			ঘূৰাই r;
		}
		sshbuf_reset(ts->cin);
	}
	যেতিয়ালৈ (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		যদি ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != রিক্ত, &sn)) != 0) {
			debug_fr(r, "S->C");
			ভঙ্গ;
		}
		debug_f("C:");
		যদি ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != রিক্ত, &cn)) != 0) {
			debug_fr(r, "C->S");
			ভঙ্গ;
		}
		যদি (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			ভঙ্গ;
		}
	}
	debug_fr(r, "done");
	ঘূৰাই r;
}

স্থির শূন্য
store_চাবি(সংরচনা shared_state *st, সংরচনা sshkey *pubkey,
    সংরচনা sshkey *privkey)
{
	যদি (st == রিক্ত || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != রিক্ত))
		abort();
	যদি ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (সংরচনা sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, পরিমাণ(*st->pubkeys));
		st->privkeys = (সংরচনা sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, পরিমাণ(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

স্থির পূর্ণাঙ্ক
prepare_চাবিগুলি(সংরচনা shared_state *st)
{
	যদি (prepare_চাবি(st, চাবি_RSA, 2048) != 0 ||
	    prepare_চাবি(st, চাবি_ECDSA, 256) != 0 ||
	    prepare_চাবি(st, চাবি_ED25519, 256) != 0) {
		error_f("key prepare failed");
		ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

স্থির সংরচনা sshkey *
get_pubkey(সংরচনা shared_state *st, পূর্ণাঙ্ক keytype)
{
	যদি (st == রিক্ত || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == রিক্ত || st->pubkeys[keytype] == রিক্ত)
		abort();
	ঘূৰাই st->pubkeys[keytype];
}

স্থির সংরচনা sshkey *
get_privkey(সংরচনা shared_state *st, পূর্ণাঙ্ক keytype)
{
	যদি (st == রিক্ত || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == রিক্ত || st->privkeys[keytype] == রিক্ত)
		abort();
	ঘূৰাই st->privkeys[keytype];
}

স্থির পূর্ণাঙ্ক
build_proposal_side(ৱর্ণ **out, ধ্রুৱ ৱর্ণ *defaults[PROPOSAL_MAX],
    ধ্রুৱ ৱর্ণ *kex, ধ্রুৱ ৱর্ণ *keyname,
    ধ্রুৱ ৱর্ণ *cipher, ধ্রুৱ ৱর্ণ *mac, ধ্রুৱ ৱর্ণ *comp)
{
	পূর্ণাঙ্ক i;
	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুৱ ৱর্ণ *ccp = defaults[i];
#ifdef CIPHER_NONE_AVAIL
		যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			ccp = "none";
#endif
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			ccp = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS && kex != রিক্ত)
			ccp = kex;
		অন্যথা যদি ((i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC) && cipher != রিক্ত)
			ccp = cipher;
		অন্যথা যদি ((i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC) && mac != রিক্ত)
			ccp = mac;
		অন্যথা যদি ((i == PROPOSAL_COMP_ALGS_CTOS ||
		    i == PROPOSAL_COMP_ALGS_STOC) && comp != রিক্ত)
			ccp = comp;
		যদি ((out[i] = strdup(ccp)) == রিক্ত)
			ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
do_kex_with_চাবি(সংরচনা shared_state *st, সংরচনা test_state *ts,
    ধ্রুৱ ৱর্ণ *kex, পূর্ণাঙ্ক keytype, ধ্রুৱ সংরচনা kex_overrides *ov)
{
	সংরচনা ssh *client = রিক্ত, *server = রিক্ত;
	সংরচনা sshkey *privkey = রিক্ত, *pubkey = রিক্ত;
	সংরচনা sshbuf *state = রিক্ত;
	সংরচনা kex_params kex_params;
	ধ্রুৱ ৱর্ণ *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ৱর্ণ *myproposal[PROPOSAL_MAX] = {0};
	ৱর্ণ *keyname = রিক্ত;
	পূর্ণাঙ্ক i, r;

	ts->cin = ts->sin = রিক্ত;
	যদি (ts->c_template != রিক্ত &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == রিক্ত)
		abort();
	যদি (ts->s_template != রিক্ত &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == রিক্ত)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	যদি (ts->cin != রিক্ত) {
		debug_f("%s %s clobber client %zu", kex, keyname,
		    sshbuf_len(ts->cin));
	} অন্যথা যদি (ts->sin != রিক্ত) {
		debug_f("%s %s clobber server %zu", kex, keyname,
		    sshbuf_len(ts->sin));
	} অন্যথা
		debug_f("%s %s noclobber", kex, keyname);

	যদি (build_proposal_side(myproposal, proposal, kex, keyname,
	    ov ? ov->cipher : রিক্ত,
	    ov ? ov->mac : রিক্ত,
	    ov ? ov->comp : রিক্ত) != 0) {
		error_f("build proposal");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ fail;
	}
	memcpy(kex_params.proposal, myproposal, পরিমাণ(myproposal));
	যদি ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		গচ্ছ fail;
	}
	যদি ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		গচ্ছ fail;
	}
	যদি ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		গচ্ছ fail;
	}
	যদি ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		গচ্ছ fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	বাবে (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	মুক্ত(keyname);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
prepare_চাবি(সংরচনা shared_state *st, পূর্ণাঙ্ক kt, পূর্ণাঙ্ক bits)
{
	ধ্রুৱ ৱর্ণ *pubstr = রিক্ত;
	ধ্রুৱ ৱর্ণ *privstr = রিক্ত;
	ৱর্ণ *tmp, *cp;
	সংরচনা sshkey *privkey = রিক্ত, *pubkey = রিক্ত;
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r;

	ৱিকল্প (kt) {
	পক্ষ চাবি_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		ভঙ্গ;
	পক্ষ চাবি_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		ভঙ্গ;
	পক্ষ চাবি_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		ভঙ্গ;
	স্ৱভাৱ:
		abort();
	}
	যদি ((b = sshbuf_from(privstr, strlen(privstr))) == রিক্ত)
		abort();
	যদি ((r = sshkey_parse_private_fileblob(b, "", &privkey, রিক্ত)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	যদি ((pubkey = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
		abort();
	যদি ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	মুক্ত(tmp);

	store_চাবি(st, pubkey, privkey);
	ঘূৰাই 0;
}

#যদি defined(STANDALONE)

#যদি 0 /* use this if generating new keys to embed above */
স্থির পূর্ণাঙ্ক
prepare_চাবি(সংরচনা shared_state *st, পূর্ণাঙ্ক keytype, পূর্ণাঙ্ক bits)
{
	সংরচনা sshkey *privkey = রিক্ত, *pubkey = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	যদি ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_চাবি(st, pubkey, privkey);
	ঘূৰাই 0;
}
#endif

পূর্ণাঙ্ক main(শূন্য)
{
	স্থির সংরচনা shared_state *st;
	সংরচনা test_state *ts;
	ধ্রুৱ পূর্ণাঙ্ক keytypes[] = { চাবি_RSA, চাবি_ECDSA, চাবি_ED25519, -1 };
	স্থির ধ্রুৱ ৱর্ণ * ধ্রুৱ kextypes[] = {
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha1",
		রিক্ত,
	};
	পূর্ণাঙ্ক i, j;
	ৱর্ণ *path;
	FILE *f;

	log_init("kex_fuzz", SYSLOG_LEVEL_DEBUG3, SYSLOG_FACILITY_AUTH, 1);

	যদি (st == রিক্ত) {
		st = (সংরচনা shared_state *)xcalloc(1, পরিমাণ(*st));
		prepare_চাবিগুলি(st);
	}
	/* Run each kex method for each key and save client/server packets */
	বাবে (i = 0; keytypes[i] != -1; i++) {
		বাবে (j = 0; kextypes[j] != রিক্ত; j++) {
			ts = (সংরচনা test_state *)xcalloc(1, পরিমাণ(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_চাবি(st, ts, kextypes[j], keytypes[i], রিক্ত);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			যদি ((f = fopen(path, "wb+")) == রিক্ত)
				abort();
			যদি (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			মুক্ত(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			যদি ((f = fopen(path, "wb+")) == রিক্ত)
				abort();
			যদি (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			মুক্ত(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			মুক্ত(ts);
		}
	}
	বাবে (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		যদি (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, রিক্ত, 0) != 0)
			abort();
		মুক্ত(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		যদি (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		মুক্ত(path);
	}
}
#অন্যথা /* !STANDALONE */
স্থির শূন্য
do_kex(সংরচনা shared_state *st, সংরচনা test_state *ts, ধ্রুৱ ৱর্ণ *kex)
{
	do_kex_with_চাবি(st, ts, kex, চাবি_RSA, রিক্ত);
	do_kex_with_চাবি(st, ts, kex, চাবি_ECDSA, রিক্ত);
	do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, রিক্ত);
}

/*
 * Run one full KEX per variant on the cheapest kex+key combo
 * (curve25519 + ed25519) so cipher/MAC/compression/mismatch paths get
 * exercised once per fuzz input without multiplying total attempts.
 */
স্থির শূন্য
kex_extras(সংরচনা shared_state *st, সংরচনা test_state *ts)
{
	স্থির ধ্রুৱ ৱর্ণ * ধ্রুৱ ciphers[] = {
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-ctr",
		"aes256-ctr",
		রিক্ত,
	};
	স্থির ধ্রুৱ ৱর্ণ * ধ্রুৱ macs[] = {
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
		রিক্ত,
	};
	স্থির ধ্রুৱ ৱর্ণ * ধ্রুৱ comps[] = {
		"zlib@openssh.com",
		"zlib",
		রিক্ত,
	};
	ধ্রুৱ ৱর্ণ *kex = "curve25519-sha256@libssh.org";
	পূর্ণাঙ্ক i;

	বাবে (i = 0; ciphers[i] != রিক্ত; i++) {
		সংরচনা kex_overrides ov = { 0 };
		ov.cipher = ciphers[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
	বাবে (i = 0; macs[i] != রিক্ত; i++) {
		সংরচনা kex_overrides ov = { 0 };
		ov.cipher = "aes128-ctr";
		ov.mac = macs[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
	বাবে (i = 0; comps[i] != রিক্ত; i++) {
		সংরচনা kex_overrides ov = { 0 };
		ov.comp = comps[i];
		do_kex_with_চাবি(st, ts, kex, চাবি_ED25519, &ov);
	}
}

স্থির শূন্য
kex_tests(সংরচনা shared_state *st, সংরচনা test_state *ts)
{
	do_kex(st, ts, "mlkem768x25519-sha256");
	do_kex(st, ts, "sntrup761x25519-sha512@openssh.com");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
	do_kex(st, ts, "diffie-hellman-group-exchange-sha1");
	kex_extras(st, ts);
}

পূর্ণাঙ্ক LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t* data, size_t size)
{
	স্থির সংরচনা shared_state *st;
	সংরচনা test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_সাৰিগুলি * 4];
	u_char zbuf[4096] = {0};
	স্থির LogLevel loglevel = SYSLOG_LEVEL_INFO;

	যদি (st == রিক্ত) {
		যদি (getenv("DEBUG") != রিক্ত || getenv("KEX_FUZZ_DEBUG") != রিক্ত)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (সংরচনা shared_state *)xcalloc(1, পরিমাণ(*st));
		prepare_চাবিগুলি(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', পরিমাণ(crbuf));

	ts = (সংরচনা test_state *)xcalloc(1, পরিমাণ(*ts));
	যদি ((ts->s_template = sshbuf_new()) == রিক্ত ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, পরিমাণ(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, পরিমাণ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	মুক্ত(ts);

	ts = (সংরচনা test_state *)xcalloc(1, পরিমাণ(*ts));
	যদি ((ts->c_template = sshbuf_new()) == রিক্ত ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, পরিমাণ(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, পরিমাণ(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	মুক্ত(ts);

	ঘূৰাই 0;
}
#endif /* STANDALONE */
} /* extern "C" */
