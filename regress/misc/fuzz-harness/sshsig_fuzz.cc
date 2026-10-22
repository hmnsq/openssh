// cc_fuzz_target test for sshsig verification.

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی "C" {

#شامل "includes.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sshsig.h"
#شامل "log.h"

صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t* sig, size_t slen)
{
  ایستا ثابت نویسه *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ساختار sshbuf *signature = sshbuf_from(sig, slen);
  ساختار sshbuf *message = sshbuf_from(data, strlen(data));
  ساختار sshkey *k = پوچ;
  ساختار sshkey_sig_details *details = پوچ;
  بیرونی نویسه *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  بازگشت 0;
}

} // extern
