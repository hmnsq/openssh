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

صحيح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* sig, ناپ_t slen)
{
  ساكن ثابت حرف *انکڑے = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  بنية sshbuf *signature = sshbuf_from(sig, slen);
  بنية sshbuf *سنیہا = sshbuf_from(انکڑے, لڑی_لمبائی(انکڑے));
  بنية sshkey *k = عدم;
  بنية sshkey_sig_details *details = عدم;
  خارجي حرف *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, سنیہا, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(سنیہا);
  أرجع 0;
}

} // extern
