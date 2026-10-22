// cc_fuzz_target test for public key parsing.

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య "C" {

#అన్తర్భావ "includes.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"

స్థిర నిర్మాణం sshkey *generate_or_die(పూర్ణాంకం type, గుర్తులేని బిట్లు) {
  పూర్ణాంకం r;
  నిర్మాణం sshkey *ret;
  ఒకవేళ ((r = sshkey_generate(type, బిట్లు, &ret)) != 0) {
    fprintf(stderr, "generate(%d, %u): %s", type, బిట్లు, ssh_err(r));
    abort();
  }
  తిరిగి ret;
}

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* sig, కొలత_t slen)
{
#నిర్వచితమైతే WITH_OPENSSL
  స్థిర నిర్మాణం sshkey *rsa = generate_or_die(కీలకం_RSA, 2048);
  స్థిర నిర్మాణం sshkey *ecdsa256 = generate_or_die(కీలకం_ECDSA, 256);
  స్థిర నిర్మాణం sshkey *ecdsa384 = generate_or_die(కీలకం_ECDSA, 384);
  స్థిర నిర్మాణం sshkey *ecdsa521 = generate_or_die(కీలకం_ECDSA, 521);
#అయితే_ముగింపు
  నిర్మాణం sshkey_sig_details *details = ఖాళీ;
  స్థిర నిర్మాణం sshkey *ed25519 = generate_or_die(కీలకం_ED25519, 0);
  స్థిర స్థిరరాశి అక్షరం *దత్తాంశం = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  స్థిర స్థిరరాశి కొలత_t dlen = అక్షరశ్రేణి_పొడవు(దత్తాంశం);

#నిర్వచితమైతే WITH_OPENSSL
  sshkey_verify(rsa, sig, slen, (స్థిరరాశి u_char *)దత్తాంశం, dlen, ఖాళీ, 0, &details);
  sshkey_sig_details_free(details);
  details = ఖాళీ;

  sshkey_verify(ecdsa256, sig, slen, (స్థిరరాశి u_char *)దత్తాంశం, dlen, ఖాళీ, 0, &details);
  sshkey_sig_details_free(details);
  details = ఖాళీ;

  sshkey_verify(ecdsa384, sig, slen, (స్థిరరాశి u_char *)దత్తాంశం, dlen, ఖాళీ, 0, &details);
  sshkey_sig_details_free(details);
  details = ఖాళీ;

  sshkey_verify(ecdsa521, sig, slen, (స్థిరరాశి u_char *)దత్తాంశం, dlen, ఖాళీ, 0, &details);
  sshkey_sig_details_free(details);
  details = ఖాళీ;
#అయితే_ముగింపు

  sshkey_verify(ed25519, sig, slen, (స్థిరరాశి u_char *)దత్తాంశం, dlen, ఖాళీ, 0, &details);
  sshkey_sig_details_free(details);
  తిరిగి 0;
}

} // extern
