/*	$OpenBSD: rijndael.h,v 1.15 2021/09/28 11:14:50 dtucker Exp $ */

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#నిర్వచితం_కాకపోతే వ్యక్తిగత_RIJNDAEL_H
#నిర్వచించు వ్యక్తిగత_RIJNDAEL_H

#నిర్వచించు AES_MAXKEYBITS	(256)
#నిర్వచించు AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#నిర్వచించు AES_MAXROUNDS	14

రకనిర్వచనం గుర్తులేని అక్షరం	u8;
రకనిర్వచనం గుర్తులేని పొట్టి	u16;
రకనిర్వచనం గుర్తులేని పూర్ణాంకం	u32;

పూర్ణాంకం	rijndael_కీలకం_అమరిక_Enc(గుర్తులేని పూర్ణాంకం [], స్థిరరాశి గుర్తులేని అక్షరం [], పూర్ణాంకం);
శూన్య	rijndaelEncrypt(స్థిరరాశి గుర్తులేని పూర్ణాంకం [], పూర్ణాంకం, స్థిరరాశి u8 [16], u8 [16]);

/*  The structure for key information */
రకనిర్వచనం నిర్మాణం {
	పూర్ణాంకం	decrypt;
	పూర్ణాంకం	Nr;		/* key-length-dependent number of rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u32	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

శూన్య	 rijndael_సమితి_కీలకం(rijndael_ctx *, u_char *, పూర్ణాంకం, పూర్ణాంకం);
శూన్య	 rijndael_decrypt(rijndael_ctx *, u_char *, u_char *);
శూన్య	 rijndael_encrypt(rijndael_ctx *, u_char *, u_char *);

#అయితే_ముగింపు /* _PRIVATE_RIJNDAEL_H */
