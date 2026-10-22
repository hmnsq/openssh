// cc_fuzz_target test for sshsig verification.

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య "C" {

#అన్తర్భావ "includes.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshsig.h"
#అన్తర్భావ "log.h"

పూర్ణాంకం LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t* sig, కొలత_t slen)
{
  స్థిర స్థిరరాశి అక్షరం *దత్తాంశం = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  నిర్మాణం sshbuf *signature = sshbuf_from(sig, slen);
  నిర్మాణం sshbuf *సందేశం_2 = sshbuf_from(దత్తాంశం, అక్షరశ్రేణి_పొడవు(దత్తాంశం));
  నిర్మాణం sshkey *k = ఖాళీ;
  నిర్మాణం sshkey_sig_details *details = ఖాళీ;
  బాహ్య అక్షరం *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, సందేశం_2, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(సందేశం_2);
  తిరిగి 0;
}

} // extern
