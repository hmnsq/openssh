// cc_fuzz_target test for sshsig verification.

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshsig.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t* sig, size_t slen)
{
  ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ସଂରଚନା sshbuf *signature = sshbuf_from(sig, slen);
  ସଂରଚନା sshbuf *message = sshbuf_from(data, strlen(data));
  ସଂରଚନା sshkey *k = ଖାଲି;
  ସଂରଚନା sshkey_sig_details *details = ଖାଲି;
  ବାହ୍ୟ ଅକ୍ଷର *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  ଫେରନ୍ତୁ 0;
}

} // extern
