// cc_fuzz_target test for sshsig verification.

#شامل <stddef.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

خارجی "C" {

#شامل "includes.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sshsig.h"
#شامل "log.h"

صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t* sig, سائز_t slen)
{
  ساکن ثابت حرف *ڈیٹا = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ساخت sshbuf *signature = sshbuf_from(sig, slen);
  ساخت sshbuf *پیغام_2 = sshbuf_from(ڈیٹا, لڑی_لمبائی(ڈیٹا));
  ساخت sshkey *k = تہی;
  ساخت sshkey_sig_details *details = تہی;
  خارجی حرف *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, پیغام_2, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(پیغام_2);
  واپس 0;
}

} // extern
