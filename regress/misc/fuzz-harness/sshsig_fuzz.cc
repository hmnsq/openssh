// cc_fuzz_target test for sshsig verification.

#ضمن <stddef.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي "C" {

#ضمن "includes.h"
#ضمن "sshkey.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "log.h"

صحيح LLVMFuzzer_Test_One_شغرو(ثابت uint8_t* sig, size_t slen)
{
  ساكن ثابت حرف *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  بنية sshbuf *signature = sshbuf_from(sig, slen);
  بنية sshbuf *message = sshbuf_from(data, strlen(data));
  بنية sshkey *k = عدم;
  بنية sshkey_sig_details *details = عدم;
  خارجي حرف *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  أرجع 0;
}

} // extern
