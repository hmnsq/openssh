/* $OpenBSD: pkcs11.h,v 1.4 2025/07/25 13:06:07 djm Exp $ */
/* pkcs11.h
   Copyright 2006, 2007 g10 Code GmbH
   Copyright 2006 Andreas Jellinghaus

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.  */

/* Please submit changes back to the Scute project at
   http://www.scute.org/ (or send them to marcus@g10code.com), so that
   they can be picked up by other projects from there as well.  */

/* This file is a modified implementation of the PKCS #11 standard by
   RSA Security Inc.  It is mostly a drop-in replacement, with the
   following change:

   This header file does not require any macro definitions by the user
   (like CK_DEFINE_FUNCTION etc).  In fact, it defines those macros
   for you (if useful, some are missing, let me know if you need
   more).

   There is an additional API available that does comply better to the
   GNU coding standard.  It can be switched on by defining
   CRYPTOKI_GNU before including this header file.  For this, the
   following changes are made to the specification:

   All structure types are changed to a "struct ck_foo" where CK_FOO
   is the type name in PKCS #11.

   All non-structure types are changed to ck_foo_t where CK_FOO is the
   lowercase version of the type name in PKCS #11.  The basic types
   (CK_ULONG et al.) are removed without substitute.

   All members of structures are modified in the following way: Type
   indication prefixes are removed, and underscore characters are
   inserted before words.  Then the result is lowercased.

   Note that function names are still in the original case, as they
   need for ABI compatibility.

   CK_FALSE, CK_TRUE and NULL_PTR are removed without substitute.  Use
   <stdbool.h>.

   If CRYPTOKI_COMPAT is defined before including this header file,
   then none of the API changes above take place, and the API is the
   one defined by the PKCS #11 standard.  */

#నిర్వచితం_కాకపోతే PKCS11_H
#నిర్వచించు PKCS11_H 1

#ఒకవేళ defined(__cplusplus)
బాహ్య "C" {
#అయితే_ముగింపు


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#నిర్వచించు CRYPTOKI_సంస్కరణ_MAJOR		3
#నిర్వచించు CRYPTOKI_సంస్కరణ_MINOR		0
#నిర్వచించు CRYPTOKI_సంస్కరణ_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#నిర్వచితం_కాకపోతే CRYPTOKI_GNU
#నిర్వచితం_కాకపోతే CRYPTOKI_COMPAT
#నిర్వచించు CRYPTOKI_COMPAT 1
#అయితే_ముగింపు
#అయితే_ముగింపు

/* System dependencies.  */

#ఒకవేళ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#సూచన pack(నెట్టు, cryptoki, 1)

#నిర్వచితమైతే CRYPTOKI_EXPORTS
#నిర్వచించు CK_SPEC __declspec(dllexport)
#లేకపోతే
#నిర్వచించు CK_SPEC __declspec(dllimport)
#అయితే_ముగింపు

#లేకపోతే

#నిర్వచించు CK_SPEC

#అయితే_ముగింపు

#నిర్వచితమైతే CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#నిర్వచించు ck_flags_t CK_FLAGS
#నిర్వచించు ck_సంస్కరణ CK_సంస్కరణ

#నిర్వచించు ck_info _CK_INFO
#నిర్వచించు cryptoki_సంస్కరణ cryptoki_సంస్కరణ_2
#నిర్వచించు manufacturer_id manufacturerID
#నిర్వచించు library_description libraryDescription
#నిర్వచించు library_సంస్కరణ library_సంస్కరణ_2

#నిర్వచించు ck_notification_t CK_NOTIFICATION
#నిర్వచించు ck_స్థానం_id_t CK_స్థానం_ID

#నిర్వచించు ck_స్థానం_info CK_స్థానం_INFO
#నిర్వచించు స్థానం_description స్థానం_Description
#నిర్వచించు hardware_సంస్కరణ hardware_సంస్కరణ_2
#నిర్వచించు firmware_సంస్కరణ firmware_సంస్కరణ_2

#నిర్వచించు ck_token_info _CK_TOKEN_INFO
#నిర్వచించు serial_సంఖ్య serial_సంఖ్య_2
#నిర్వచించు max_session_లెక్క ul_Max_Session_లెక్క
#నిర్వచించు session_లెక్క ul_Session_లెక్క
#నిర్వచించు max_rw_session_లెక్క ul_Max_Rw_Session_లెక్క
#నిర్వచించు rw_session_లెక్క ul_Rw_Session_లెక్క
#నిర్వచించు max_pin_len ulMaxPinLen
#నిర్వచించు min_pin_len ulMinPinLen
#నిర్వచించు మొత్తం_ప్రజా_జ్ఞాపకం ul_మొత్తం_ప్రజా_జ్ఞాపకం
#నిర్వచించు free_ప్రజా_జ్ఞాపకం ul_Free_ప్రజా_జ్ఞాపకం
#నిర్వచించు మొత్తం_వ్యక్తిగత_జ్ఞాపకం ul_మొత్తం_వ్యక్తిగత_జ్ఞాపకం
#నిర్వచించు free_వ్యక్తిగత_జ్ఞాపకం ul_Free_వ్యక్తిగత_జ్ఞాపకం
#నిర్వచించు utc_సమయం utc_సమయం_2

#నిర్వచించు ck_session_handle_t CK_SESSION_HANDLE
#నిర్వచించు ck_user_type_t CK_USER_TYPE
#నిర్వచించు ck_state_t CK_STATE

#నిర్వచించు ck_session_info _CK_SESSION_INFO
#నిర్వచించు స్థానం_id స్థానం_ID
#నిర్వచించు device_error ulDeviceError

#నిర్వచించు ck_object_handle_t CK_OBJECT_HANDLE
#నిర్వచించు ck_object_class_t CK_OBJECT_CLASS
#నిర్వచించు ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#నిర్వచించు ck_కీలకం_type_t CK_కీలకం_TYPE
#నిర్వచించు ck_certificate_type_t CK_CERTIFICATE_TYPE
#నిర్వచించు ck_attribute_type_t CK_ATTRIBUTE_TYPE

#నిర్వచించు ck_attribute _CK_ATTRIBUTE
#నిర్వచించు విలువ p_విలువ
#నిర్వచించు విలువ_len ul_విలువ_Len

#నిర్వచించు ck_date _CK_DATE

#నిర్వచించు ck_mechanism_type_t CK_MECHANISM_TYPE

#నిర్వచించు ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#నిర్వచించు ck_mechanism _CK_MECHANISM
#నిర్వచించు parameter pParameter
#నిర్వచించు parameter_len ulParameterLen

#నిర్వచించు ck_mechanism_info _CK_MECHANISM_INFO
#నిర్వచించు min_కీలకం_కొలత ul_Min_కీలకం_కొలత
#నిర్వచించు max_కీలకం_కొలత ul_Max_కీలకం_కొలత

#నిర్వచించు ck_rv_t CK_RV
#నిర్వచించు ck_notify_t CK_NOTIFY

#నిర్వచించు ck_interface CK_INTERFACE

#నిర్వచించు ck_function_list _CK_FUNCTION_LIST
#నిర్వచించు ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#నిర్వచించు ck_createmutex_t CK_CREATEMUTEX
#నిర్వచించు ck_destroymutex_t CK_DESTROYMUTEX
#నిర్వచించు ck_lockmutex_t CK_LOCKMUTEX
#నిర్వచించు ck_unlockmutex_t CK_UNLOCKMUTEX

#నిర్వచించు ck_c_initialize_వాదనలు CK_C_INITIALIZE_వాదనలు
#నిర్వచించు create_mutex CreateMutex
#నిర్వచించు destroy_mutex DestroyMutex
#నిర్వచించు తాళం_mutex తాళం_Mutex
#నిర్వచించు unlock_mutex UnlockMutex
#నిర్వచించు reserved pReserved

#అయితే_ముగింపు	/* CRYPTOKI_COMPAT */


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_flags_t;

నిర్మాణం ck_సంస్కరణ
{
  గుర్తులేని అక్షరం major;
  గుర్తులేని అక్షరం minor;
};


నిర్మాణం ck_info
{
  నిర్మాణం ck_సంస్కరణ cryptoki_సంస్కరణ;
  గుర్తులేని అక్షరం manufacturer_id[32];
  ck_flags_t flags;
  గుర్తులేని అక్షరం library_description[32];
  నిర్మాణం ck_సంస్కరణ library_సంస్కరణ;
};


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_notification_t;

#నిర్వచించు CKN_SURRENDER	(0UL)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_స్థానం_id_t;


నిర్మాణం ck_స్థానం_info
{
  గుర్తులేని అక్షరం స్థానం_description[64];
  గుర్తులేని అక్షరం manufacturer_id[32];
  ck_flags_t flags;
  నిర్మాణం ck_సంస్కరణ hardware_సంస్కరణ;
  నిర్మాణం ck_సంస్కరణ firmware_సంస్కరణ;
};


#నిర్వచించు CKF_TOKEN_PRESENT	(1UL << 0)
#నిర్వచించు CKF_REMOVABLE_DEVICE	(1UL << 1)
#నిర్వచించు CKF_HW_స్థానం		(1UL << 2)
#నిర్వచించు CKF_ARRAY_ATTRIBUTE	(1UL << 30)


నిర్మాణం ck_token_info
{
  గుర్తులేని అక్షరం label[32];
  గుర్తులేని అక్షరం manufacturer_id[32];
  గుర్తులేని అక్షరం model[16];
  గుర్తులేని అక్షరం serial_సంఖ్య[16];
  ck_flags_t flags;
  గుర్తులేని దీర్ఘ max_session_లెక్క;
  గుర్తులేని దీర్ఘ session_లెక్క;
  గుర్తులేని దీర్ఘ max_rw_session_లెక్క;
  గుర్తులేని దీర్ఘ rw_session_లెక్క;
  గుర్తులేని దీర్ఘ max_pin_len;
  గుర్తులేని దీర్ఘ min_pin_len;
  గుర్తులేని దీర్ఘ మొత్తం_ప్రజా_జ్ఞాపకం;
  గుర్తులేని దీర్ఘ free_ప్రజా_జ్ఞాపకం;
  గుర్తులేని దీర్ఘ మొత్తం_వ్యక్తిగత_జ్ఞాపకం;
  గుర్తులేని దీర్ఘ free_వ్యక్తిగత_జ్ఞాపకం;
  నిర్మాణం ck_సంస్కరణ hardware_సంస్కరణ;
  నిర్మాణం ck_సంస్కరణ firmware_సంస్కరణ;
  గుర్తులేని అక్షరం utc_సమయం[16];
};


#నిర్వచించు CKF_RNG					(1UL << 0)
#నిర్వచించు CKF_WRITE_PROTECTED			(1UL << 1)
#నిర్వచించు CKF_LOGIN_REQUIRED			(1UL << 2)
#నిర్వచించు CKF_USER_PIN_INITIALIZED		(1UL << 3)
#నిర్వచించు CKF_RESTORE_కీలకం_NOT_NEEDED		(1UL << 5)
#నిర్వచించు CKF_CLOCK_ON_TOKEN			(1UL << 6)
#నిర్వచించు CKF_PROTECTED_AUTHENTICATION_మార్గం	(1UL << 8)
#నిర్వచించు CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#నిర్వచించు CKF_TOKEN_INITIALIZED			(1UL << 10)
#నిర్వచించు CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#నిర్వచించు CKF_USER_PIN_లెక్క_దిగువ			(1UL << 16)
#నిర్వచించు CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#నిర్వచించు CKF_USER_PIN_LOCKED			(1UL << 18)
#నిర్వచించు CKF_USER_PIN_గమ్యం_BE_మారింది		(1UL << 19)
#నిర్వచించు CKF_SO_PIN_లెక్క_దిగువ			(1UL << 20)
#నిర్వచించు CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#నిర్వచించు CKF_SO_PIN_LOCKED			(1UL << 22)
#నిర్వచించు CKF_SO_PIN_గమ్యం_BE_మారింది		(1UL << 23)

#నిర్వచించు CK_UNAVAILABLE_INFORMATION	((గుర్తులేని దీర్ఘ) -1)
#నిర్వచించు CK_EFFECTIVELY_INFINITE		(0UL)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_session_handle_t;

#నిర్వచించు CK_INVALID_HANDLE	(0UL)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_user_type_t;

#నిర్వచించు CKU_SO			(0UL)
#నిర్వచించు CKU_USER		(1UL)
#నిర్వచించు CKU_CONTEXT_SPECIFIC	(2UL)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_state_t;

#నిర్వచించు CKS_RO_ప్రజా_SESSION	(0UL)
#నిర్వచించు CKS_RO_USER_FUNCTIONS	(1UL)
#నిర్వచించు CKS_RW_ప్రజా_SESSION	(2UL)
#నిర్వచించు CKS_RW_USER_FUNCTIONS	(3UL)
#నిర్వచించు CKS_RW_SO_FUNCTIONS	(4UL)


నిర్మాణం ck_session_info
{
  ck_స్థానం_id_t స్థానం_id;
  ck_state_t state;
  ck_flags_t flags;
  గుర్తులేని దీర్ఘ device_error;
};

#నిర్వచించు CKF_RW_SESSION		(1UL << 1)
#నిర్వచించు CKF_SERIAL_SESSION	(1UL << 2)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_object_handle_t;


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_object_class_t;

#నిర్వచించు CKO_దత్తాంశం		(0UL)
#నిర్వచించు CKO_CERTIFICATE		(1UL)
#నిర్వచించు CKO_ప్రజా_కీలకం		(2UL)
#నిర్వచించు CKO_వ్యక్తిగత_కీలకం		(3UL)
#నిర్వచించు CKO_SECRET_కీలకం		(4UL)
#నిర్వచించు CKO_HW_FEATURE		(5UL)
#నిర్వచించు CKO_DOMAIN_PARAMETERS	(6UL)
#నిర్వచించు CKO_MECHANISM		(7UL)
#నిర్వచించు CKO_OTP_కీలకం		(8UL)
#నిర్వచించు CKO_PROFILE		(9UL)
#నిర్వచించు CKO_VENDOR_DEFINED	(1UL << 31)

#నిర్వచించు CKP_INVALID_ID                (0UL)
#నిర్వచించు CKP_BASELINE_PROVIDER         (1UL)
#నిర్వచించు CKP_EXTENDED_PROVIDER         (2UL)
#నిర్వచించు CKP_AUTHENTICATION_TOKEN      (3UL)
#నిర్వచించు CKP_ప్రజా_CERTIFICATES_TOKEN (4UL)
#నిర్వచించు CKP_VENDOR_DEFINED            (1UL << 31)

రకనిర్వచనం గుర్తులేని దీర్ఘ ck_hw_feature_type_t;

#నిర్వచించు CKH_MONOTONIC_COUNTER	(1UL)
#నిర్వచించు CKH_CLOCK		(2UL)
#నిర్వచించు CKH_USER_INTERFACE	(3UL)
#నిర్వచించు CKH_VENDOR_DEFINED	(1UL << 31)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_కీలకం_type_t;

#నిర్వచించు CKK_RSA			(0UL)
#నిర్వచించు CKK_DSA			(1UL)
#నిర్వచించు CKK_DH			(2UL)
#నిర్వచించు CKK_ECDSA		(3UL)
#నిర్వచించు CKK_EC			(3UL)
#నిర్వచించు CKK_X9_42_DH		(4UL)
#నిర్వచించు CKK_KEA			(5UL)
#నిర్వచించు CKK_GENERIC_SECRET	(0x10UL)
#నిర్వచించు CKK_RC2			(0x11UL)
#నిర్వచించు CKK_RC4			(0x12UL)
#నిర్వచించు CKK_DES			(0x13UL)
#నిర్వచించు CKK_DES2		(0x14UL)
#నిర్వచించు CKK_DES3		(0x15UL)
#నిర్వచించు CKK_CAST		(0x16UL)
#నిర్వచించు CKK_CAST3		(0x17UL)
#నిర్వచించు CKK_CAST128		(0x18UL)
#నిర్వచించు CKK_RC5			(0x19UL)
#నిర్వచించు CKK_IDEA		(0x1aUL)
#నిర్వచించు CKK_SKIPJACK		(0x1bUL)
#నిర్వచించు CKK_BATON		(0x1cUL)
#నిర్వచించు CKK_JUNIPER		(0x1dUL)
#నిర్వచించు CKK_CDMF		(0x1eUL)
#నిర్వచించు CKK_AES			(0x1fUL)
#నిర్వచించు CKK_BLOWFISH		(0x20UL)
#నిర్వచించు CKK_TWOFISH		(0x21UL)
#నిర్వచించు CKK_GOSTR3410		(0x30UL)
#నిర్వచించు CKK_GOSTR3411		(0x31UL)
#నిర్వచించు CKK_GOST28147		(0x32UL)
#నిర్వచించు CKK_EC_EDWARDS		(0x40UL)
#నిర్వచించు CKK_EC_MONTGOMERY	(0x41UL)
#నిర్వచించు CKK_HKDF		(0x42UL)
#నిర్వచించు CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#నిర్వచించు NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#నిర్వచించు CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#నిర్వచించు CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

రకనిర్వచనం గుర్తులేని దీర్ఘ ck_certificate_type_t;

#నిర్వచించు CKC_X_509		(0UL)
#నిర్వచించు CKC_X_509_ATTR_CERT	(1UL)
#నిర్వచించు CKC_WTLS		(2UL)
#నిర్వచించు CKC_VENDOR_DEFINED	(1UL << 31)


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_attribute_type_t;

#నిర్వచించు CKA_CLASS			(0UL)
#నిర్వచించు CKA_TOKEN			(1UL)
#నిర్వచించు CKA_వ్యక్తిగత			(2UL)
#నిర్వచించు CKA_LABEL			(3UL)
#నిర్వచించు CKA_UNIQUE_ID		(4UL)
#నిర్వచించు CKA_APPLICATION			(0x10UL)
#నిర్వచించు CKA_విలువ			(0x11UL)
#నిర్వచించు CKA_OBJECT_ID			(0x12UL)
#నిర్వచించు CKA_CERTIFICATE_TYPE		(0x80UL)
#నిర్వచించు CKA_ISSUER			(0x81UL)
#నిర్వచించు CKA_SERIAL_సంఖ్య		(0x82UL)
#నిర్వచించు CKA_AC_ISSUER			(0x83UL)
#నిర్వచించు CKA_OWNER			(0x84UL)
#నిర్వచించు CKA_ATTR_TYPES			(0x85UL)
#నిర్వచించు CKA_TRUSTED			(0x86UL)
#నిర్వచించు CKA_CERTIFICATE_CATEGORY	(0x87UL)
#నిర్వచించు CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#నిర్వచించు CKA_URL				(0x89UL)
#నిర్వచించు CKA_HASH_యొక్క_SUBJECT_ప్రజా_కీలకం	(0x8aUL)
#నిర్వచించు CKA_HASH_యొక్క_ISSUER_ప్రజా_కీలకం	(0x8bUL)
#నిర్వచించు CKA_CHECK_విలువ			(0x90UL)
#నిర్వచించు CKA_కీలకం_TYPE			(0x100UL)
#నిర్వచించు CKA_SUBJECT			(0x101UL)
#నిర్వచించు CKA_ID				(0x102UL)
#నిర్వచించు CKA_SENSITIVE			(0x103UL)
#నిర్వచించు CKA_ENCRYPT			(0x104UL)
#నిర్వచించు CKA_DECRYPT			(0x105UL)
#నిర్వచించు CKA_WRAP			(0x106UL)
#నిర్వచించు CKA_UNWRAP			(0x107UL)
#నిర్వచించు CKA_SIGN			(0x108UL)
#నిర్వచించు CKA_SIGN_RECOVER		(0x109UL)
#నిర్వచించు CKA_VERIFY			(0x10aUL)
#నిర్వచించు CKA_VERIFY_RECOVER		(0x10bUL)
#నిర్వచించు CKA_DERIVE			(0x10cUL)
#నిర్వచించు CKA_ప్రారంభం_DATE			(0x110UL)
#నిర్వచించు CKA_చివర_DATE			(0x111UL)
#నిర్వచించు CKA_MODULUS			(0x120UL)
#నిర్వచించు CKA_MODULUS_బిట్లు		(0x121UL)
#నిర్వచించు CKA_ప్రజా_EXPONENT		(0x122UL)
#నిర్వచించు CKA_వ్యక్తిగత_EXPONENT		(0x123UL)
#నిర్వచించు CKA_ప్రధానసంఖ్య_1			(0x124UL)
#నిర్వచించు CKA_ప్రధానసంఖ్య_2			(0x125UL)
#నిర్వచించు CKA_EXPONENT_1			(0x126UL)
#నిర్వచించు CKA_EXPONENT_2			(0x127UL)
#నిర్వచించు CKA_COEFFICIENT			(0x128UL)
#నిర్వచించు CKA_ప్రజా_కీలకం_INFO		(0x129UL)
#నిర్వచించు CKA_ప్రధానసంఖ్య			(0x130UL)
#నిర్వచించు CKA_SUBPRIME			(0x131UL)
#నిర్వచించు CKA_పునాది			(0x132UL)
#నిర్వచించు CKA_ప్రధానసంఖ్య_బిట్లు			(0x133UL)
#నిర్వచించు CKA_SUB_ప్రధానసంఖ్య_బిట్లు		(0x134UL)
#నిర్వచించు CKA_విలువ_బిట్లు			(0x160UL)
#నిర్వచించు CKA_విలువ_LEN			(0x161UL)
#నిర్వచించు CKA_EXTRACTABLE			(0x162UL)
#నిర్వచించు CKA_LOCAL			(0x163UL)
#నిర్వచించు CKA_NEVER_EXTRACTABLE		(0x164UL)
#నిర్వచించు CKA_ALWAYS_SENSITIVE		(0x165UL)
#నిర్వచించు CKA_కీలకం_GEN_MECHANISM		(0x166UL)
#నిర్వచించు CKA_MODIFIABLE			(0x170UL)
#నిర్వచించు CKA_COPYABLE			(0x171UL)
#నిర్వచించు CKA_DESTROYABLE			(0x172UL)
#నిర్వచించు CKA_ECDSA_PARAMS		(0x180UL)
#నిర్వచించు CKA_EC_PARAMS			(0x180UL)
#నిర్వచించు CKA_EC_బిందువు			(0x181UL)
#నిర్వచించు CKA_SECONDARY_AUTH		(0x200UL)
#నిర్వచించు CKA_AUTH_PIN_FLAGS		(0x201UL)
#నిర్వచించు CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#నిర్వచించు CKA_WRAP_WITH_TRUSTED		(0x210UL)
#నిర్వచించు CKA_GOSTR3410_PARAMS		(0x250UL)
#నిర్వచించు CKA_GOSTR3411_PARAMS		(0x251UL)
#నిర్వచించు CKA_GOST28147_PARAMS		(0x252UL)
#నిర్వచించు CKA_HW_FEATURE_TYPE		(0x300UL)
#నిర్వచించు CKA_RESET_ON_INIT		(0x301UL)
#నిర్వచించు CKA_HAS_RESET			(0x302UL)
#నిర్వచించు CKA_PIXEL_X			(0x400UL)
#నిర్వచించు CKA_PIXEL_Y			(0x401UL)
#నిర్వచించు CKA_RESOLUTION			(0x402UL)
#నిర్వచించు CKA_CHAR_అడ్డువరుసలు			(0x403UL)
#నిర్వచించు CKA_CHAR_COLUMNS		(0x404UL)
#నిర్వచించు CKA_COLOR			(0x405UL)
#నిర్వచించు CKA_బిట్లు_చొప్పున_PIXEL		(0x406UL)
#నిర్వచించు CKA_CHAR_SETS			(0x480UL)
#నిర్వచించు CKA_ENCODING_METHODS		(0x481UL)
#నిర్వచించు CKA_MIME_TYPES			(0x482UL)
#నిర్వచించు CKA_MECHANISM_TYPE		(0x500UL)
#నిర్వచించు CKA_REQUIRED_CMS_లక్షణాలు	(0x501UL)
#నిర్వచించు CKA_DEFAULT_CMS_లక్షణాలు	(0x502UL)
#నిర్వచించు CKA_SUPPORTED_CMS_లక్షణాలు	(0x503UL)
#నిర్వచించు CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#నిర్వచించు CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#నిర్వచించు CKA_OTP_FORMAT			(0x220UL)
#నిర్వచించు CKA_OTP_నిడివి			(0x221UL)
#నిర్వచించు CKA_OTP_సమయం_INTERVAL		(0x222UL)
#నిర్వచించు CKA_OTP_USER_FRIENDLY_బహుళకం	(0x223UL)
#నిర్వచించు CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#నిర్వచించు CKA_OTP_సమయం_REQUIREMENT	(0x225UL)
#నిర్వచించు CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#నిర్వచించు CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#నిర్వచించు CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#నిర్వచించు CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#నిర్వచించు CKA_OTP_SERVICE_LOGO		(0x22CUL)
#నిర్వచించు CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#నిర్వచించు CKA_OTP_COUNTER			(0x22EUL)
#నిర్వచించు CKA_OTP_సమయం			(0x22FUL)
#నిర్వచించు CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#నిర్వచించు CKA_PROFILE_ID			(0x601UL)
#నిర్వచించు CKA_VENDOR_DEFINED		(1UL << 31)


నిర్మాణం ck_attribute
{
  ck_attribute_type_t type;
  శూన్య *విలువ;
  గుర్తులేని దీర్ఘ విలువ_len;
};


నిర్మాణం ck_date
{
  గుర్తులేని అక్షరం year[4];
  గుర్తులేని అక్షరం month[2];
  గుర్తులేని అక్షరం day[2];
};


రకనిర్వచనం గుర్తులేని దీర్ఘ ck_mechanism_type_t;

#నిర్వచించు CKM_RSA_PKCS_కీలకం_PAIR_GEN	(0UL)
#నిర్వచించు CKM_RSA_PKCS			(1UL)
#నిర్వచించు CKM_RSA_9796			(2UL)
#నిర్వచించు CKM_RSA_X_509			(3UL)
#నిర్వచించు CKM_MD2_RSA_PKCS		(4UL)
#నిర్వచించు CKM_MD5_RSA_PKCS		(5UL)
#నిర్వచించు CKM_SHA1_RSA_PKCS		(6UL)
#నిర్వచించు CKM_RIPEMD128_RSA_PKCS		(7UL)
#నిర్వచించు CKM_RIPEMD160_RSA_PKCS		(8UL)
#నిర్వచించు CKM_RSA_PKCS_OAEP		(9UL)
#నిర్వచించు CKM_RSA_X9_31_కీలకం_PAIR_GEN	(0xaUL)
#నిర్వచించు CKM_RSA_X9_31			(0xbUL)
#నిర్వచించు CKM_SHA1_RSA_X9_31		(0xcUL)
#నిర్వచించు CKM_RSA_PKCS_PSS		(0xdUL)
#నిర్వచించు CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#నిర్వచించు CKM_DSA_కీలకం_PAIR_GEN		(0x10UL)
#నిర్వచించు	CKM_DSA				(0x11UL)
#నిర్వచించు CKM_DSA_SHA1			(0x12UL)
#నిర్వచించు CKM_DSA_SHA224			(0x13UL)
#నిర్వచించు CKM_DSA_SHA256			(0x14UL)
#నిర్వచించు CKM_DSA_SHA384			(0x15UL)
#నిర్వచించు CKM_DSA_SHA512			(0x16UL)
#నిర్వచించు CKM_DH_PKCS_కీలకం_PAIR_GEN	(0x20UL)
#నిర్వచించు CKM_DH_PKCS_DERIVE		(0x21UL)
#నిర్వచించు	CKM_X9_42_DH_కీలకం_PAIR_GEN	(0x30UL)
#నిర్వచించు CKM_X9_42_DH_DERIVE		(0x31UL)
#నిర్వచించు CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#నిర్వచించు CKM_X9_42_MQV_DERIVE		(0x33UL)
#నిర్వచించు CKM_SHA256_RSA_PKCS		(0x40UL)
#నిర్వచించు CKM_SHA384_RSA_PKCS		(0x41UL)
#నిర్వచించు CKM_SHA512_RSA_PKCS		(0x42UL)
#నిర్వచించు CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#నిర్వచించు CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#నిర్వచించు CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#నిర్వచించు CKM_SHA224_RSA_PKCS		(0x46UL)
#నిర్వచించు CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#నిర్వచించు CKM_SHA3_256_RSA_PKCS		(0x60UL)
#నిర్వచించు CKM_SHA3_384_RSA_PKCS		(0x61UL)
#నిర్వచించు CKM_SHA3_512_RSA_PKCS		(0x62UL)
#నిర్వచించు CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#నిర్వచించు CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#నిర్వచించు CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#నిర్వచించు CKM_SHA3_224_RSA_PKCS		(0x66UL)
#నిర్వచించు CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#నిర్వచించు CKM_RC2_కీలకం_GEN			(0x100UL)
#నిర్వచించు CKM_RC2_ECB			(0x101UL)
#నిర్వచించు	CKM_RC2_CBC			(0x102UL)
#నిర్వచించు	CKM_RC2_MAC			(0x103UL)
#నిర్వచించు CKM_RC2_MAC_GENERAL		(0x104UL)
#నిర్వచించు CKM_RC2_CBC_PAD			(0x105UL)
#నిర్వచించు CKM_RC4_కీలకం_GEN			(0x110UL)
#నిర్వచించు CKM_RC4				(0x111UL)
#నిర్వచించు CKM_DES_కీలకం_GEN			(0x120UL)
#నిర్వచించు CKM_DES_ECB			(0x121UL)
#నిర్వచించు CKM_DES_CBC			(0x122UL)
#నిర్వచించు CKM_DES_MAC			(0x123UL)
#నిర్వచించు CKM_DES_MAC_GENERAL		(0x124UL)
#నిర్వచించు CKM_DES_CBC_PAD			(0x125UL)
#నిర్వచించు CKM_DES2_కీలకం_GEN		(0x130UL)
#నిర్వచించు CKM_DES3_కీలకం_GEN		(0x131UL)
#నిర్వచించు CKM_DES3_ECB			(0x132UL)
#నిర్వచించు CKM_DES3_CBC			(0x133UL)
#నిర్వచించు CKM_DES3_MAC			(0x134UL)
#నిర్వచించు CKM_DES3_MAC_GENERAL		(0x135UL)
#నిర్వచించు CKM_DES3_CBC_PAD		(0x136UL)
#నిర్వచించు CKM_DES3_CMAC_GENERAL		(0x137UL)
#నిర్వచించు CKM_DES3_CMAC			(0x138UL)
#నిర్వచించు CKM_CDMF_కీలకం_GEN		(0x140UL)
#నిర్వచించు CKM_CDMF_ECB			(0x141UL)
#నిర్వచించు CKM_CDMF_CBC			(0x142UL)
#నిర్వచించు CKM_CDMF_MAC			(0x143UL)
#నిర్వచించు CKM_CDMF_MAC_GENERAL		(0x144UL)
#నిర్వచించు CKM_CDMF_CBC_PAD		(0x145UL)
#నిర్వచించు CKM_MD2				(0x200UL)
#నిర్వచించు CKM_MD2_HMAC			(0x201UL)
#నిర్వచించు CKM_MD2_HMAC_GENERAL		(0x202UL)
#నిర్వచించు CKM_MD5				(0x210UL)
#నిర్వచించు CKM_MD5_HMAC			(0x211UL)
#నిర్వచించు CKM_MD5_HMAC_GENERAL		(0x212UL)
#నిర్వచించు CKM_SHA_1			(0x220UL)
#నిర్వచించు CKM_SHA_1_HMAC			(0x221UL)
#నిర్వచించు CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#నిర్వచించు CKM_RIPEMD128			(0x230UL)
#నిర్వచించు CKM_RIPEMD128_HMAC		(0x231UL)
#నిర్వచించు CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#నిర్వచించు CKM_RIPEMD160			(0x240UL)
#నిర్వచించు CKM_RIPEMD160_HMAC		(0x241UL)
#నిర్వచించు CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#నిర్వచించు CKM_SHA256			(0x250UL)
#నిర్వచించు CKM_SHA256_HMAC			(0x251UL)
#నిర్వచించు CKM_SHA256_HMAC_GENERAL		(0x252UL)
#నిర్వచించు CKM_SHA224			(0x255UL)
#నిర్వచించు CKM_SHA224_HMAC			(0x256UL)
#నిర్వచించు CKM_SHA224_HMAC_GENERAL		(0x257UL)
#నిర్వచించు CKM_SHA384			(0x260UL)
#నిర్వచించు CKM_SHA384_HMAC			(0x261UL)
#నిర్వచించు CKM_SHA384_HMAC_GENERAL		(0x262UL)
#నిర్వచించు CKM_SHA512			(0x270UL)
#నిర్వచించు CKM_SHA512_HMAC			(0x271UL)
#నిర్వచించు CKM_SHA512_HMAC_GENERAL		(0x272UL)
#నిర్వచించు CKM_SHA3_256			(0x2B0UL)
#నిర్వచించు CKM_SHA3_256_HMAC		(0x2B1UL)
#నిర్వచించు CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#నిర్వచించు CKM_SHA3_256_కీలకం_GEN		(0x2B3UL)
#నిర్వచించు CKM_SHA3_224			(0x2B5UL)
#నిర్వచించు CKM_SHA3_224_HMAC		(0x2B6UL)
#నిర్వచించు CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#నిర్వచించు CKM_SHA3_224_కీలకం_GEN		(0x2B8UL)
#నిర్వచించు CKM_SHA3_384			(0x2C0UL)
#నిర్వచించు CKM_SHA3_384_HMAC		(0x2C1UL)
#నిర్వచించు CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#నిర్వచించు CKM_SHA3_384_కీలకం_GEN		(0x2C3UL)
#నిర్వచించు CKM_SHA3_512			(0x2D0UL)
#నిర్వచించు CKM_SHA3_512_HMAC		(0x2D1UL)
#నిర్వచించు CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#నిర్వచించు CKM_SHA3_512_కీలకం_GEN		(0x2D3UL)
#నిర్వచించు CKM_CAST_కీలకం_GEN		(0x300UL)
#నిర్వచించు CKM_CAST_ECB			(0x301UL)
#నిర్వచించు CKM_CAST_CBC			(0x302UL)
#నిర్వచించు CKM_CAST_MAC			(0x303UL)
#నిర్వచించు CKM_CAST_MAC_GENERAL		(0x304UL)
#నిర్వచించు CKM_CAST_CBC_PAD		(0x305UL)
#నిర్వచించు CKM_CAST3_కీలకం_GEN		(0x310UL)
#నిర్వచించు CKM_CAST3_ECB			(0x311UL)
#నిర్వచించు CKM_CAST3_CBC			(0x312UL)
#నిర్వచించు CKM_CAST3_MAC			(0x313UL)
#నిర్వచించు CKM_CAST3_MAC_GENERAL		(0x314UL)
#నిర్వచించు CKM_CAST3_CBC_PAD		(0x315UL)
#నిర్వచించు CKM_CAST5_కీలకం_GEN		(0x320UL)
#నిర్వచించు CKM_CAST128_కీలకం_GEN		(0x320UL)
#నిర్వచించు CKM_CAST5_ECB			(0x321UL)
#నిర్వచించు CKM_CAST128_ECB			(0x321UL)
#నిర్వచించు CKM_CAST5_CBC			(0x322UL)
#నిర్వచించు CKM_CAST128_CBC			(0x322UL)
#నిర్వచించు CKM_CAST5_MAC			(0x323UL)
#నిర్వచించు	CKM_CAST128_MAC			(0x323UL)
#నిర్వచించు CKM_CAST5_MAC_GENERAL		(0x324UL)
#నిర్వచించు CKM_CAST128_MAC_GENERAL		(0x324UL)
#నిర్వచించు CKM_CAST5_CBC_PAD		(0x325UL)
#నిర్వచించు CKM_CAST128_CBC_PAD		(0x325UL)
#నిర్వచించు CKM_RC5_కీలకం_GEN			(0x330UL)
#నిర్వచించు CKM_RC5_ECB			(0x331UL)
#నిర్వచించు CKM_RC5_CBC			(0x332UL)
#నిర్వచించు CKM_RC5_MAC			(0x333UL)
#నిర్వచించు CKM_RC5_MAC_GENERAL		(0x334UL)
#నిర్వచించు CKM_RC5_CBC_PAD			(0x335UL)
#నిర్వచించు CKM_IDEA_కీలకం_GEN		(0x340UL)
#నిర్వచించు CKM_IDEA_ECB			(0x341UL)
#నిర్వచించు	CKM_IDEA_CBC			(0x342UL)
#నిర్వచించు CKM_IDEA_MAC			(0x343UL)
#నిర్వచించు CKM_IDEA_MAC_GENERAL		(0x344UL)
#నిర్వచించు CKM_IDEA_CBC_PAD		(0x345UL)
#నిర్వచించు CKM_GENERIC_SECRET_కీలకం_GEN	(0x350UL)
#నిర్వచించు CKM_CONCATENATE_పునాది_AND_కీలకం	(0x360UL)
#నిర్వచించు CKM_CONCATENATE_పునాది_AND_దత్తాంశం	(0x362UL)
#నిర్వచించు CKM_CONCATENATE_దత్తాంశం_AND_పునాది	(0x363UL)
#నిర్వచించు CKM_XOR_పునాది_AND_దత్తాంశం		(0x364UL)
#నిర్వచించు CKM_వెలికితీయి_కీలకం_FROM_కీలకం	(0x365UL)
#నిర్వచించు CKM_SSL3_PRE_MASTER_కీలకం_GEN	(0x370UL)
#నిర్వచించు CKM_SSL3_MASTER_కీలకం_DERIVE	(0x371UL)
#నిర్వచించు CKM_SSL3_కీలకం_AND_MAC_DERIVE	(0x372UL)
#నిర్వచించు CKM_SSL3_MASTER_కీలకం_DERIVE_DH	(0x373UL)
#నిర్వచించు CKM_TLS_PRE_MASTER_కీలకం_GEN	(0x374UL)
#నిర్వచించు CKM_TLS_MASTER_కీలకం_DERIVE	(0x375UL)
#నిర్వచించు CKM_TLS_కీలకం_AND_MAC_DERIVE	(0x376UL)
#నిర్వచించు CKM_TLS_MASTER_కీలకం_DERIVE_DH	(0x377UL)
#నిర్వచించు CKM_SSL3_MD5_MAC		(0x380UL)
#నిర్వచించు CKM_SSL3_SHA1_MAC		(0x381UL)
#నిర్వచించు CKM_MD5_కీలకం_DERIVATION		(0x390UL)
#నిర్వచించు CKM_MD2_కీలకం_DERIVATION		(0x391UL)
#నిర్వచించు CKM_SHA1_కీలకం_DERIVATION		(0x392UL)
#నిర్వచించు CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#నిర్వచించు CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#నిర్వచించు CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#నిర్వచించు CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#నిర్వచించు CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#నిర్వచించు CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#నిర్వచించు CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#నిర్వచించు CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#నిర్వచించు CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#నిర్వచించు CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#నిర్వచించు CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#నిర్వచించు CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#నిర్వచించు CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#నిర్వచించు CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#నిర్వచించు CKM_PKCS5_PBKD2			(0x3b0UL)
#నిర్వచించు CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#నిర్వచించు CKM_కీలకం_WRAP_LYNKS		(0x400UL)
#నిర్వచించు CKM_కీలకం_WRAP_సమితి_OAEP		(0x401UL)
#నిర్వచించు CKM_SKIPJACK_కీలకం_GEN		(0x1000UL)
#నిర్వచించు CKM_SKIPJACK_ECB64		(0x1001UL)
#నిర్వచించు CKM_SKIPJACK_CBC64		(0x1002UL)
#నిర్వచించు CKM_SKIPJACK_OFB64		(0x1003UL)
#నిర్వచించు CKM_SKIPJACK_CFB64		(0x1004UL)
#నిర్వచించు CKM_SKIPJACK_CFB32		(0x1005UL)
#నిర్వచించు CKM_SKIPJACK_CFB16		(0x1006UL)
#నిర్వచించు CKM_SKIPJACK_CFB8		(0x1007UL)
#నిర్వచించు CKM_SKIPJACK_WRAP		(0x1008UL)
#నిర్వచించు CKM_SKIPJACK_వ్యక్తిగత_WRAP	(0x1009UL)
#నిర్వచించు CKM_SKIPJACK_RELAYX		(0x100aUL)
#నిర్వచించు CKM_KEA_కీలకం_PAIR_GEN		(0x1010UL)
#నిర్వచించు CKM_KEA_కీలకం_DERIVE		(0x1011UL)
#నిర్వచించు CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#నిర్వచించు CKM_BATON_కీలకం_GEN		(0x1030UL)
#నిర్వచించు CKM_BATON_ECB128		(0x1031UL)
#నిర్వచించు CKM_BATON_ECB96			(0x1032UL)
#నిర్వచించు CKM_BATON_CBC128		(0x1033UL)
#నిర్వచించు CKM_BATON_COUNTER		(0x1034UL)
#నిర్వచించు CKM_BATON_SHUFFLE		(0x1035UL)
#నిర్వచించు CKM_BATON_WRAP			(0x1036UL)
#నిర్వచించు CKM_ECDSA_కీలకం_PAIR_GEN		(0x1040UL)
#నిర్వచించు CKM_EC_కీలకం_PAIR_GEN		(0x1040UL)
#నిర్వచించు CKM_ECDSA			(0x1041UL)
#నిర్వచించు CKM_ECDSA_SHA1			(0x1042UL)
#నిర్వచించు CKM_ECDSA_SHA224		(0x1043UL)
#నిర్వచించు CKM_ECDSA_SHA256		(0x1044UL)
#నిర్వచించు CKM_ECDSA_SHA384		(0x1045UL)
#నిర్వచించు CKM_ECDSA_SHA512		(0x1046UL)
#నిర్వచించు CKM_ECDSA_SHA3_224		(0x1047UL)
#నిర్వచించు CKM_ECDSA_SHA3_256		(0x1048UL)
#నిర్వచించు CKM_ECDSA_SHA3_384		(0x1049UL)
#నిర్వచించు CKM_ECDSA_SHA3_512		(0x104AUL)
#నిర్వచించు CKM_ECDH1_DERIVE		(0x1050UL)
#నిర్వచించు CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#నిర్వచించు CKM_ECMQV_DERIVE		(0x1052UL)
#నిర్వచించు CKM_EC_EDWARDS_కీలకం_PAIR_GEN     (0x1055UL)
#నిర్వచించు CKM_EC_MONTGOMERY_కీలకం_PAIR_GEN  (0x1056UL)
#నిర్వచించు CKM_EDDSA			(0x1057UL)
#నిర్వచించు CKM_JUNIPER_కీలకం_GEN		(0x1060UL)
#నిర్వచించు CKM_JUNIPER_ECB128		(0x1061UL)
#నిర్వచించు CKM_JUNIPER_CBC128		(0x1062UL)
#నిర్వచించు CKM_JUNIPER_COUNTER		(0x1063UL)
#నిర్వచించు CKM_JUNIPER_SHUFFLE		(0x1064UL)
#నిర్వచించు CKM_JUNIPER_WRAP		(0x1065UL)
#నిర్వచించు CKM_FASTHASH			(0x1070UL)
#నిర్వచించు CKM_AES_కీలకం_GEN			(0x1080UL)
#నిర్వచించు CKM_AES_ECB			(0x1081UL)
#నిర్వచించు CKM_AES_CBC			(0x1082UL)
#నిర్వచించు CKM_AES_MAC			(0x1083UL)
#నిర్వచించు CKM_AES_MAC_GENERAL		(0x1084UL)
#నిర్వచించు CKM_AES_CBC_PAD			(0x1085UL)
#నిర్వచించు CKM_AES_CTR				(0x1086UL)
#నిర్వచించు CKM_AES_GCM				(0x1087UL)
#నిర్వచించు CKM_AES_CCM				(0x1088UL)
#నిర్వచించు CKM_AES_CTS				(0x1089UL)
#నిర్వచించు CKM_AES_CMAC			(0x108AUL)
#నిర్వచించు CKM_AES_CMAC_GENERAL		(0x108BUL)
#నిర్వచించు CKM_AES_XCBC_MAC		(0x108CUL)
#నిర్వచించు CKM_AES_XCBC_MAC_96		(0x108DUL)
#నిర్వచించు CKM_AES_GMAC			(0x108EUL)
#నిర్వచించు CKM_BLOWFISH_కీలకం_GEN    (0x1090UL)
#నిర్వచించు CKM_BLOWFISH_CBC        (0x1091UL)
#నిర్వచించు CKM_TWOFISH_కీలకం_GEN     (0x1092UL)
#నిర్వచించు CKM_TWOFISH_CBC         (0x1093UL)
#నిర్వచించు CKM_DES_ECB_ENCRYPT_దత్తాంశం	(0x1100UL)
#నిర్వచించు CKM_DES_CBC_ENCRYPT_దత్తాంశం	(0x1101UL)
#నిర్వచించు CKM_DES3_ECB_ENCRYPT_దత్తాంశం	(0x1102UL)
#నిర్వచించు CKM_DES3_CBC_ENCRYPT_దత్తాంశం	(0x1103UL)
#నిర్వచించు CKM_AES_ECB_ENCRYPT_దత్తాంశం	(0x1104UL)
#నిర్వచించు CKM_AES_CBC_ENCRYPT_దత్తాంశం	(0x1105UL)
#నిర్వచించు CKM_GOSTR3410_కీలకం_PAIR_GEN	(0x1200UL)
#నిర్వచించు CKM_GOSTR3410			(0x1201UL)
#నిర్వచించు CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#నిర్వచించు CKM_GOSTR3410_కీలకం_WRAP  (0x1203UL)
#నిర్వచించు CKM_GOSTR3410_DERIVE    (0x1204UL)
#నిర్వచించు CKM_GOSTR3410_512_కీలకం_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#నిర్వచించు CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#నిర్వచించు CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#నిర్వచించు CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#నిర్వచించు CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#నిర్వచించు CKM_GOSTR3411			(0x1210UL)
#నిర్వచించు CKM_GOSTR3411_HMAC      (0x1211UL)
#నిర్వచించు CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#నిర్వచించు CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#నిర్వచించు CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#నిర్వచించు CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#నిర్వచించు CKM_GOST28147_కీలకం_GEN   (0x1220UL)
#నిర్వచించు CKM_GOST28147_ECB       (0x1221UL)
#నిర్వచించు CKM_GOST28147           (0x1222UL)
#నిర్వచించు CKM_GOST28147_MAC       (0x1223UL)
#నిర్వచించు CKM_GOST28147_కీలకం_WRAP  (0x1224UL)

#నిర్వచించు CKM_DSA_PARAMETER_GEN		(0x2000UL)
#నిర్వచించు CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#నిర్వచించు CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#నిర్వచించు CKM_AES_OFB			(0x2104UL)
#నిర్వచించు CKM_AES_CFB64			(0x2105UL)
#నిర్వచించు CKM_AES_CFB8			(0x2106UL)
#నిర్వచించు CKM_AES_CFB128			(0x2107UL)
#నిర్వచించు CKM_AES_CFB1			(0x2108UL)
#నిర్వచించు CKM_AES_కీలకం_WRAP		(0x2109UL)
#నిర్వచించు CKM_AES_కీలకం_WRAP_PAD		(0x210AUL)
#నిర్వచించు CKM_XEDDSA			(0x4029UL)
#నిర్వచించు CKM_HKDF_DERIVE			(0x402AUL)
#నిర్వచించు CKM_HKDF_దత్తాంశం			(0x402BUL)
#నిర్వచించు CKM_HKDF_కీలకం_GEN		(0x402CUL)

#నిర్వచించు CKM_VENDOR_DEFINED		(1UL << 31)

నిర్మాణం ck_mechanism
{
  ck_mechanism_type_t mechanism;
  శూన్య *parameter;
  గుర్తులేని దీర్ఘ parameter_len;
};


నిర్మాణం ck_mechanism_info
{
  గుర్తులేని దీర్ఘ min_కీలకం_కొలత;
  గుర్తులేని దీర్ఘ max_కీలకం_కొలత;
  ck_flags_t flags;
};

#నిర్వచించు CKF_HW			(1UL << 0)

#నిర్వచించు CKF_సందేశం_ENCRYPT	(1UL << 1)
#నిర్వచించు CKF_సందేశం_DECRYPT	(1UL << 2)
#నిర్వచించు CKF_సందేశం_SIGN	(1UL << 3)
#నిర్వచించు CKF_సందేశం_VERIFY	(1UL << 4)
#నిర్వచించు CKF_MULTI_సందేశం	(1UL << 5)
#నిర్వచించు CKF_కనుగొను_OBJECTS	(1UL << 6)

#నిర్వచించు CKF_ENCRYPT		(1UL << 8)
#నిర్వచించు CKF_DECRYPT		(1UL << 9)
#నిర్వచించు CKF_DIGEST		(1UL << 10)
#నిర్వచించు CKF_SIGN		(1UL << 11)
#నిర్వచించు CKF_SIGN_RECOVER	(1UL << 12)
#నిర్వచించు CKF_VERIFY		(1UL << 13)
#నిర్వచించు CKF_VERIFY_RECOVER	(1UL << 14)
#నిర్వచించు CKF_GENERATE		(1UL << 15)
#నిర్వచించు CKF_GENERATE_కీలకం_PAIR	(1UL << 16)
#నిర్వచించు CKF_WRAP		(1UL << 17)
#నిర్వచించు CKF_UNWRAP		(1UL << 18)
#నిర్వచించు CKF_DERIVE		(1UL << 19)
#నిర్వచించు CKF_EXTENSION		(1UL << 31)

#నిర్వచించు CKF_EC_F_P			(1UL << 20)
#నిర్వచించు CKF_EC_F_2M			(1UL << 21)
#నిర్వచించు CKF_EC_ECPARAMETERS	(1UL << 22)
#నిర్వచించు CKF_EC_OID		(1UL << 23)
#నిర్వచించు CKF_EC_NAMEDCURVE	CKF_EC_OID
#నిర్వచించు CKF_EC_UNCOMPRESS	(1UL << 24)
#నిర్వచించు CKF_EC_COMPRESS		(1UL << 25)
#నిర్వచించు CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#నిర్వచించు CKF_DONT_ఖండం				(1UL)

/* Flags for Key derivation */
#నిర్వచించు CKD_NULL			(0x1UL)
#నిర్వచించు CKD_SHA1_KDF			(0x2UL)
#నిర్వచించు CKD_SHA224_KDF			(0x5UL)
#నిర్వచించు CKD_SHA256_KDF			(0x6UL)
#నిర్వచించు CKD_SHA384_KDF			(0x7UL)
#నిర్వచించు CKD_SHA512_KDF			(0x8UL)

రకనిర్వచనం నిర్మాణం CK_ECDH1_DERIVE_PARAMS {
	గుర్తులేని దీర్ఘ  kdf;
	గుర్తులేని దీర్ఘ  ul_Shared_దత్తాంశం_Len;
	గుర్తులేని అక్షరం *  p_Shared_దత్తాంశం;
	గుర్తులేని దీర్ఘ  ul_ప్రజా_దత్తాంశం_Len;
	గుర్తులేని అక్షరం *  p_ప్రజా_దత్తాంశం;
} CK_ECDH1_DERIVE_PARAMS;

రకనిర్వచనం నిర్మాణం CK_ECMQV_DERIVE_PARAMS {
	గుర్తులేని దీర్ఘ kdf;
	గుర్తులేని దీర్ఘ ul_Shared_దత్తాంశం_Len;
	గుర్తులేని అక్షరం * p_Shared_దత్తాంశం;
	గుర్తులేని దీర్ఘ ul_ప్రజా_దత్తాంశం_Len;
	గుర్తులేని అక్షరం * p_ప్రజా_దత్తాంశం;
	గుర్తులేని దీర్ఘ ul_వ్యక్తిగత_దత్తాంశం_Len;
	CK_OBJECT_HANDLE h_వ్యక్తిగత_దత్తాంశం;
	గుర్తులేని దీర్ఘ ul_ప్రజా_దత్తాంశం_Len2;
	గుర్తులేని అక్షరం * p_ప్రజా_Data2;
	CK_OBJECT_HANDLE ప్రజా_కీలకం_2;
} CK_ECMQV_DERIVE_PARAMS;

రకనిర్వచనం గుర్తులేని దీర్ఘ ck_rsa_pkcs_mgf_type_t;
రకనిర్వచనం గుర్తులేని దీర్ఘ CK_RSA_PKCS_OAEP_ఆధారం_TYPE;

రకనిర్వచనం నిర్మాణం CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_ఆధారం_TYPE ఆధారం;
	శూన్య *p_ఆధారం_దత్తాంశం;
	గుర్తులేని దీర్ఘ ul_ఆధారం_దత్తాంశం_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

రకనిర్వచనం నిర్మాణం CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	గుర్తులేని దీర్ఘ sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#నిర్వచించు CKG_MGF1_SHA1			(0x00000001UL)
#నిర్వచించు CKG_MGF1_SHA224		(0x00000005UL)
#నిర్వచించు CKG_MGF1_SHA256		(0x00000002UL)
#నిర్వచించు CKG_MGF1_SHA384		(0x00000003UL)
#నిర్వచించు CKG_MGF1_SHA512		(0x00000004UL)
#నిర్వచించు CKG_MGF1_SHA3_224	(0x00000006UL)
#నిర్వచించు CKG_MGF1_SHA3_256	(0x00000007UL)
#నిర్వచించు CKG_MGF1_SHA3_384	(0x00000008UL)
#నిర్వచించు CKG_MGF1_SHA3_512	(0x00000009UL)

#నిర్వచించు CKZ_దత్తాంశం_SPECIFIED	(0x00000001UL)

రకనిర్వచనం నిర్మాణం CK_GCM_PARAMS {
	శూన్య * pIv;
	గుర్తులేని దీర్ఘ ulIvLen;
	గుర్తులేని దీర్ఘ ul_Iv_బిట్లు;
	శూన్య * pAAD;
	గుర్తులేని దీర్ఘ ulAADLen;
	గుర్తులేని దీర్ఘ ul_ట్యాగ్_బిట్లు;
} CK_GCM_PARAMS;

రకనిర్వచనం నిర్మాణం CK_CCM_PARAMS {
	గుర్తులేని దీర్ఘ ul_దత్తాంశం_Len;
	గుర్తులేని అక్షరం *pNonce;
	గుర్తులేని దీర్ఘ ulNonceLen;
	గుర్తులేని అక్షరం *pAAD;
	గుర్తులేని దీర్ఘ ulAADLen;
	గుర్తులేని దీర్ఘ ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
రకనిర్వచనం నిర్మాణం CK_EDDSA_PARAMS {
	గుర్తులేని అక్షరం phFlag;
	గుర్తులేని దీర్ఘ ul_Context_దత్తాంశం_Len;
	గుర్తులేని అక్షరం *p_Context_దత్తాంశం;
} CK_EDDSA_PARAMS;

రకనిర్వచనం CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
రకనిర్వచనం నిర్మాణం CK_XEDDSA_PARAMS {
	గుర్తులేని దీర్ఘ hash;
} CK_XEDDSA_PARAMS;

రకనిర్వచనం CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

రకనిర్వచనం నిర్మాణం CK_AES_CTR_PARAMS {
    గుర్తులేని దీర్ఘ ul_Counter_బిట్లు;
    గుర్తులేని అక్షరం cb[16];
} CK_AES_CTR_PARAMS;

రకనిర్వచనం CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

రకనిర్వచనం గుర్తులేని దీర్ఘ CK_MAC_GENERAL_PARAMS;

రకనిర్వచనం CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

రకనిర్వచనం గుర్తులేని దీర్ఘ ck_rv_t;


రకనిర్వచనం ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, శూన్య *application);

నిర్మాణం ck_interface {
  అక్షరం * pInterfaceName;
  శూన్య * pFunctionList;
  ck_flags_t flags;
};

#నిర్వచించు CKF_INTERFACE_FORK_సురక్షిత	(0x00000001UL)

/* Forward reference.  */
నిర్మాణం ck_function_list;
నిర్మాణం ck_function_list_3_0;

#నిర్వచించు _CK_DECLARE_FUNCTION(name, వాదనలు)	\
రకనిర్వచనం ck_rv_t (*CK_ ## name) వాదనలు;		\
ck_rv_t CK_SPEC name వాదనలు

_CK_DECLARE_FUNCTION (C_Initialize, (శూన్య *init_వాదనలు));
_CK_DECLARE_FUNCTION (C_Finalize, (శూన్య *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (నిర్మాణం ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (నిర్మాణం ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_స్థానం_List,
		      (గుర్తులేని అక్షరం token_present, ck_స్థానం_id_t *స్థానం_list,
		       గుర్తులేని దీర్ఘ *లెక్క));
_CK_DECLARE_FUNCTION (C_Get_స్థానం_Info,
		      (ck_స్థానం_id_t స్థానం_id, నిర్మాణం ck_స్థానం_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_స్థానం_id_t స్థానం_id, నిర్మాణం ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_స్థానం_Event,
		      (ck_flags_t flags, ck_స్థానం_id_t *స్థానం, శూన్య *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_స్థానం_id_t స్థానం_id,
		       ck_mechanism_type_t *mechanism_list,
		       గుర్తులేని దీర్ఘ *లెక్క));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_స్థానం_id_t స్థానం_id, ck_mechanism_type_t type,
		       నిర్మాణం ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_స్థానం_id_t స్థానం_id, గుర్తులేని అక్షరం *pin,
		       గుర్తులేని దీర్ఘ pin_len, గుర్తులేని అక్షరం *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, గుర్తులేని అక్షరం *pin,
		       గుర్తులేని దీర్ఘ pin_len));
_CK_DECLARE_FUNCTION (C_సమితి_PIN,
		      (ck_session_handle_t session, గుర్తులేని అక్షరం *old_pin,
		       గుర్తులేని దీర్ఘ old_len, గుర్తులేని అక్షరం *new_pin,
		       గుర్తులేని దీర్ఘ new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_స్థానం_id_t స్థానం_id, ck_flags_t flags,
		       శూన్య *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_స్థానం_id_t స్థానం_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *operation_state,
		       గుర్తులేని దీర్ఘ *operation_state_len));
_CK_DECLARE_FUNCTION (C_సమితి_Operation_State,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *operation_state,
		       గుర్తులేని దీర్ఘ operation_state_len,
		       ck_object_handle_t encryption_కీలకం,
		       ck_object_handle_t authentication_కీలకం));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       గుర్తులేని అక్షరం *pin, గుర్తులేని దీర్ఘ pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ లెక్క, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       నిర్మాణం ck_attribute *templ, గుర్తులేని దీర్ఘ లెక్క,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_కొలత,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       గుర్తులేని దీర్ఘ *కొలత));
_CK_DECLARE_FUNCTION (C_Get_Attribute_విలువ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ లెక్క));
_CK_DECLARE_FUNCTION (C_సమితి_Attribute_విలువ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ లెక్క));
_CK_DECLARE_FUNCTION (C_కనుగొను_Objects_Init,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ లెక్క));
_CK_DECLARE_FUNCTION (C_కనుగొను_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       గుర్తులేని దీర్ఘ max_object_లెక్క,
		       గుర్తులేని దీర్ఘ *object_లెక్క));
_CK_DECLARE_FUNCTION (C_కనుగొను_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *encrypted_దత్తాంశం,
		       గుర్తులేని దీర్ఘ *encrypted_దత్తాంశం_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *చివరి_encrypted_part,
		       గుర్తులేని దీర్ఘ *చివరి_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *encrypted_దత్తాంశం,
		       గుర్తులేని దీర్ఘ encrypted_దత్తాంశం_len,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ *దత్తాంశం_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ encrypted_part_len,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *చివరి_part,
		       గుర్తులేని దీర్ఘ *చివరి_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *digest,
		       గుర్తులేని దీర్ఘ *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len));
_CK_DECLARE_FUNCTION (C_Digest_కీలకం,
		      (ck_session_handle_t session, ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *digest,
		       గుర్తులేని దీర్ఘ *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *దత్తాంశం, గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ signature_len,
		       గుర్తులేని అక్షరం *దత్తాంశం,
		       గుర్తులేని దీర్ఘ *దత్తాంశం_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ encrypted_part_len,
		       గుర్తులేని అక్షరం *part,
		       గుర్తులేని దీర్ఘ *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *part, గుర్తులేని దీర్ఘ part_len,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *encrypted_part,
		       గుర్తులేని దీర్ఘ encrypted_part_len,
		       గుర్తులేని అక్షరం *part,
		       గుర్తులేని దీర్ఘ *part_len));

_CK_DECLARE_FUNCTION (C_Generate_కీలకం,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ లెక్క,
		       ck_object_handle_t *కీలకం));
_CK_DECLARE_FUNCTION (C_Generate_కీలకం_Pair,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       నిర్మాణం ck_attribute *ప్రజా_కీలకం_template,
		       గుర్తులేని దీర్ఘ ప్రజా_కీలకం_attribute_లెక్క,
		       నిర్మాణం ck_attribute *వ్యక్తిగత_కీలకం_template,
		       గుర్తులేని దీర్ఘ వ్యక్తిగత_కీలకం_attribute_లెక్క,
		       ck_object_handle_t *ప్రజా_కీలకం,
		       ck_object_handle_t *వ్యక్తిగత_కీలకం));
_CK_DECLARE_FUNCTION (C_Wrap_కీలకం,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_కీలకం,
		       ck_object_handle_t కీలకం,
		       గుర్తులేని అక్షరం *wrapped_కీలకం,
		       గుర్తులేని దీర్ఘ *wrapped_కీలకం_len));
_CK_DECLARE_FUNCTION (C_Unwrap_కీలకం,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_కీలకం,
		       గుర్తులేని అక్షరం *wrapped_కీలకం,
		       గుర్తులేని దీర్ఘ wrapped_కీలకం_len,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ attribute_లెక్క,
		       ck_object_handle_t *కీలకం));
_CK_DECLARE_FUNCTION (C_Derive_కీలకం,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t పునాది_కీలకం,
		       నిర్మాణం ck_attribute *templ,
		       గుర్తులేని దీర్ఘ attribute_లెక్క,
		       ck_object_handle_t *కీలకం));

_CK_DECLARE_FUNCTION (C_విత్తనం_Random,
		      (ck_session_handle_t session, గుర్తులేని అక్షరం *విత్తనం,
		       గుర్తులేని దీర్ఘ విత్తనం_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       గుర్తులేని అక్షరం *random_data,
		       గుర్తులేని దీర్ఘ random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_స్థితి, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (నిర్మాణం ck_interface *interfaces_list,
		       గుర్తులేని దీర్ఘ *లెక్క));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (గుర్తులేని అక్షరం *interface_name,
		       నిర్మాణం ck_సంస్కరణ *సంస్కరణ,
		       నిర్మాణం ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       గుర్తులేని అక్షరం *pin,
		       గుర్తులేని దీర్ఘ pin_len,
		       గుర్తులేని అక్షరం *username,
		       గుర్తులేని దీర్ఘ username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_సందేశం_Encrypt_Init,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Encrypt_సందేశం,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *associated_దత్తాంశం,
		       గుర్తులేని దీర్ఘ associated_దత్తాంశం_len,
		       గుర్తులేని అక్షరం *plaintext,
		       గుర్తులేని దీర్ఘ plaintext_len,
		       గుర్తులేని అక్షరం *ciphertext,
		       గుర్తులేని దీర్ఘ *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_సందేశం_Begin,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *associated_దత్తాంశం,
		       గుర్తులేని దీర్ఘ associated_దత్తాంశం_len));
_CK_DECLARE_FUNCTION (C_Encrypt_సందేశం_తదుపరి,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *plaintext_part,
		       గుర్తులేని దీర్ఘ plaintext_part_len,
		       గుర్తులేని అక్షరం *ciphertext_part,
		       గుర్తులేని దీర్ఘ *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_సందేశం_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_సందేశం_Decrypt_Init,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Decrypt_సందేశం,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *associated_దత్తాంశం,
		       గుర్తులేని దీర్ఘ associated_దత్తాంశం_len,
		       గుర్తులేని అక్షరం *ciphertext,
		       గుర్తులేని దీర్ఘ ciphertext_len,
		       గుర్తులేని అక్షరం *plaintext,
		       గుర్తులేని దీర్ఘ *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_సందేశం_Begin,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *associated_దత్తాంశం,
		       గుర్తులేని దీర్ఘ associated_దత్తాంశం_len));
_CK_DECLARE_FUNCTION (C_Decrypt_సందేశం_తదుపరి,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *ciphertext_part,
		       గుర్తులేని దీర్ఘ ciphertext_part_len,
		       గుర్తులేని అక్షరం *plaintext_part,
		       గుర్తులేని దీర్ఘ *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_సందేశం_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_సందేశం_Sign_Init,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Sign_సందేశం,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *దత్తాంశం,
		       గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_సందేశం_Begin,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_సందేశం_తదుపరి,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *దత్తాంశం,
		       గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ *signature_len));
_CK_DECLARE_FUNCTION (C_సందేశం_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_సందేశం_Verify_Init,
		      (ck_session_handle_t session,
		       నిర్మాణం ck_mechanism *mechanism,
		       ck_object_handle_t కీలకం));
_CK_DECLARE_FUNCTION (C_Verify_సందేశం,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *దత్తాంశం,
		       గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ signature_len));
_CK_DECLARE_FUNCTION (C_Verify_సందేశం_Begin,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_సందేశం_తదుపరి,
		      (ck_session_handle_t session,
		       శూన్య *parameter,
		       గుర్తులేని దీర్ఘ parameter_len,
		       గుర్తులేని అక్షరం *దత్తాంశం,
		       గుర్తులేని దీర్ఘ దత్తాంశం_len,
		       గుర్తులేని అక్షరం *signature,
		       గుర్తులేని దీర్ఘ signature_len));
_CK_DECLARE_FUNCTION (C_సందేశం_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#నిర్వచించు CKF_చివర_యొక్క_సందేశం	(0x00000001UL)

నిర్మాణం ck_function_list
{
  నిర్మాణం ck_సంస్కరణ సంస్కరణ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_స్థానం_List C_Get_స్థానం_List;
  CK_C_Get_స్థానం_Info C_Get_స్థానం_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_సమితి_PIN C_సమితి_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_సమితి_Operation_State C_సమితి_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_కొలత C_Get_Object_కొలత;
  CK_C_Get_Attribute_విలువ C_Get_Attribute_విలువ;
  CK_C_సమితి_Attribute_విలువ C_సమితి_Attribute_విలువ;
  CK_C_కనుగొను_Objects_Init C_కనుగొను_Objects_Init;
  CK_C_కనుగొను_Objects C_కనుగొను_Objects;
  CK_C_కనుగొను_Objects_Final C_కనుగొను_Objects_Final;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_కీలకం C_Digest_కీలకం;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_కీలకం C_Generate_కీలకం;
  CK_C_Generate_కీలకం_Pair C_Generate_కీలకం_Pair;
  CK_C_Wrap_కీలకం C_Wrap_కీలకం;
  CK_C_Unwrap_కీలకం C_Unwrap_కీలకం;
  CK_C_Derive_కీలకం C_Derive_కీలకం;
  CK_C_విత్తనం_Random C_విత్తనం_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_స్థితి C_Get_Function_స్థితి;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_స్థానం_Event C_Wait_For_స్థానం_Event;
};

నిర్మాణం ck_function_list_3_0
{
  నిర్మాణం ck_సంస్కరణ సంస్కరణ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_స్థానం_List C_Get_స్థానం_List;
  CK_C_Get_స్థానం_Info C_Get_స్థానం_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_సమితి_PIN C_సమితి_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_సమితి_Operation_State C_సమితి_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_కొలత C_Get_Object_కొలత;
  CK_C_Get_Attribute_విలువ C_Get_Attribute_విలువ;
  CK_C_సమితి_Attribute_విలువ C_సమితి_Attribute_విలువ;
  CK_C_కనుగొను_Objects_Init C_కనుగొను_Objects_Init;
  CK_C_కనుగొను_Objects C_కనుగొను_Objects;
  CK_C_కనుగొను_Objects_Final C_కనుగొను_Objects_Final;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_కీలకం C_Digest_కీలకం;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_కీలకం C_Generate_కీలకం;
  CK_C_Generate_కీలకం_Pair C_Generate_కీలకం_Pair;
  CK_C_Wrap_కీలకం C_Wrap_కీలకం;
  CK_C_Unwrap_కీలకం C_Unwrap_కీలకం;
  CK_C_Derive_కీలకం C_Derive_కీలకం;
  CK_C_విత్తనం_Random C_విత్తనం_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_స్థితి C_Get_Function_స్థితి;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_స్థానం_Event C_Wait_For_స్థానం_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_సందేశం_Encrypt_Init C_సందేశం_Encrypt_Init;
  CK_C_Encrypt_సందేశం C_Encrypt_సందేశం;
  CK_C_Encrypt_సందేశం_Begin C_Encrypt_సందేశం_Begin;
  CK_C_Encrypt_సందేశం_తదుపరి C_Encrypt_సందేశం_తదుపరి;
  CK_C_సందేశం_Encrypt_Final C_సందేశం_Encrypt_Final;
  CK_C_సందేశం_Decrypt_Init C_సందేశం_Decrypt_Init;
  CK_C_Decrypt_సందేశం C_Decrypt_సందేశం;
  CK_C_Decrypt_సందేశం_Begin C_Decrypt_సందేశం_Begin;
  CK_C_Decrypt_సందేశం_తదుపరి C_Decrypt_సందేశం_తదుపరి;
  CK_C_సందేశం_Decrypt_Final C_సందేశం_Decrypt_Final;
  CK_C_సందేశం_Sign_Init C_సందేశం_Sign_Init;
  CK_C_Sign_సందేశం C_Sign_సందేశం;
  CK_C_Sign_సందేశం_Begin C_Sign_సందేశం_Begin;
  CK_C_Sign_సందేశం_తదుపరి C_Sign_సందేశం_తదుపరి;
  CK_C_సందేశం_Sign_Final C_సందేశం_Sign_Final;
  CK_C_సందేశం_Verify_Init C_సందేశం_Verify_Init;
  CK_C_Verify_సందేశం C_Verify_సందేశం;
  CK_C_Verify_సందేశం_Begin C_Verify_సందేశం_Begin;
  CK_C_Verify_సందేశం_తదుపరి C_Verify_సందేశం_తదుపరి;
  CK_C_సందేశం_Verify_Final C_సందేశం_Verify_Final;
};



రకనిర్వచనం ck_rv_t (*ck_createmutex_t) (శూన్య **mutex);
రకనిర్వచనం ck_rv_t (*ck_destroymutex_t) (శూన్య *mutex);
రకనిర్వచనం ck_rv_t (*ck_lockmutex_t) (శూన్య *mutex);
రకనిర్వచనం ck_rv_t (*ck_unlockmutex_t) (శూన్య *mutex);


నిర్మాణం ck_c_initialize_వాదనలు
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t తాళం_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  శూన్య *reserved;
};


#నిర్వచించు CKF_LIBRARY_CANT_CREATE_OS_దారాలు	(1UL << 0)
#నిర్వచించు CKF_OS_LOCKING_OK			(1UL << 1)

#నిర్వచించు CKR_OK					(0UL)
#నిర్వచించు CKR_CANCEL				(1UL)
#నిర్వచించు CKR_HOST_జ్ఞాపకం				(2UL)
#నిర్వచించు CKR_స్థానం_ID_INVALID			(3UL)
#నిర్వచించు CKR_GENERAL_ERROR			(5UL)
#నిర్వచించు CKR_FUNCTION_FAILED			(6UL)
#నిర్వచించు CKR_ARGUMENTS_BAD			(7UL)
#నిర్వచించు CKR_NO_EVENT				(8UL)
#నిర్వచించు CKR_NEED_గమ్యం_CREATE_దారాలు		(9UL)
#నిర్వచించు CKR_CANT_తాళం				(0xaUL)
#నిర్వచించు CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#నిర్వచించు CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#నిర్వచించు CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#నిర్వచించు CKR_ATTRIBUTE_విలువ_INVALID		(0x13UL)
#నిర్వచించు CKR_ACTION_PROHIBITED			(0x1BUL)
#నిర్వచించు CKR_దత్తాంశం_INVALID			(0x20UL)
#నిర్వచించు CKR_దత్తాంశం_LEN_RANGE			(0x21UL)
#నిర్వచించు CKR_DEVICE_ERROR			(0x30UL)
#నిర్వచించు CKR_DEVICE_జ్ఞాపకం			(0x31UL)
#నిర్వచించు CKR_DEVICE_REMOVED			(0x32UL)
#నిర్వచించు CKR_ENCRYPTED_దత్తాంశం_INVALID		(0x40UL)
#నిర్వచించు CKR_ENCRYPTED_దత్తాంశం_LEN_RANGE		(0x41UL)
#నిర్వచించు CKR_FUNCTION_CANCELED			(0x50UL)
#నిర్వచించు CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#నిర్వచించు CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#నిర్వచించు CKR_కీలకం_HANDLE_INVALID			(0x60UL)
#నిర్వచించు CKR_కీలకం_కొలత_RANGE			(0x62UL)
#నిర్వచించు CKR_కీలకం_TYPE_INCONSISTENT		(0x63UL)
#నిర్వచించు CKR_కీలకం_NOT_NEEDED			(0x64UL)
#నిర్వచించు CKR_కీలకం_మారింది				(0x65UL)
#నిర్వచించు CKR_కీలకం_NEEDED				(0x66UL)
#నిర్వచించు CKR_కీలకం_INDIGESTIBLE			(0x67UL)
#నిర్వచించు CKR_కీలకం_FUNCTION_NOT_PERMITTED		(0x68UL)
#నిర్వచించు CKR_కీలకం_NOT_WRAPPABLE			(0x69UL)
#నిర్వచించు CKR_కీలకం_UNEXTRACTABLE			(0x6aUL)
#నిర్వచించు CKR_MECHANISM_INVALID			(0x70UL)
#నిర్వచించు CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#నిర్వచించు CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#నిర్వచించు CKR_OPERATION_చురుకైన			(0x90UL)
#నిర్వచించు CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#నిర్వచించు CKR_PIN_INCORRECT			(0xa0UL)
#నిర్వచించు CKR_PIN_INVALID				(0xa1UL)
#నిర్వచించు CKR_PIN_LEN_RANGE			(0xa2UL)
#నిర్వచించు CKR_PIN_EXPIRED				(0xa3UL)
#నిర్వచించు CKR_PIN_LOCKED				(0xa4UL)
#నిర్వచించు CKR_SESSION_CLOSED			(0xb0UL)
#నిర్వచించు CKR_SESSION_లెక్క			(0xb1UL)
#నిర్వచించు CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#నిర్వచించు CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#నిర్వచించు CKR_SESSION_READ_ONLY			(0xb5UL)
#నిర్వచించు CKR_SESSION_EXISTS			(0xb6UL)
#నిర్వచించు CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#నిర్వచించు CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#నిర్వచించు CKR_SIGNATURE_INVALID			(0xc0UL)
#నిర్వచించు CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#నిర్వచించు CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#నిర్వచించు CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#నిర్వచించు CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#నిర్వచించు CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#నిర్వచించు CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#నిర్వచించు	CKR_UNWRAPPING_కీలకం_HANDLE_INVALID	(0xf0UL)
#నిర్వచించు CKR_UNWRAPPING_కీలకం_కొలత_RANGE		(0xf1UL)
#నిర్వచించు CKR_UNWRAPPING_కీలకం_TYPE_INCONSISTENT	(0xf2UL)
#నిర్వచించు CKR_USER_ALREADY_LOGGED_లోపల		(0x100UL)
#నిర్వచించు CKR_USER_NOT_LOGGED_లోపల			(0x101UL)
#నిర్వచించు CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#నిర్వచించు CKR_USER_TYPE_INVALID			(0x103UL)
#నిర్వచించు CKR_USER_ANOTHER_ALREADY_LOGGED_లోపల	(0x104UL)
#నిర్వచించు CKR_USER_TOO_MANY_TYPES			(0x105UL)
#నిర్వచించు CKR_WRAPPED_కీలకం_INVALID			(0x110UL)
#నిర్వచించు CKR_WRAPPED_కీలకం_LEN_RANGE		(0x112UL)
#నిర్వచించు CKR_WRAPPING_కీలకం_HANDLE_INVALID		(0x113UL)
#నిర్వచించు CKR_WRAPPING_కీలకం_కొలత_RANGE		(0x114UL)
#నిర్వచించు CKR_WRAPPING_కీలకం_TYPE_INCONSISTENT	(0x115UL)
#నిర్వచించు CKR_RANDOM_విత్తనం_NOT_SUPPORTED		(0x120UL)
#నిర్వచించు CKR_RANDOM_NO_RNG			(0x121UL)
#నిర్వచించు CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#నిర్వచించు CKR_వక్రం_NOT_SUPPORTED			(0x140UL)
#నిర్వచించు CKR_బఫరు_TOO_SMALL			(0x150UL)
#నిర్వచించు CKR_SAVED_STATE_INVALID			(0x160UL)
#నిర్వచించు CKR_INFORMATION_SENSITIVE		(0x170UL)
#నిర్వచించు CKR_STATE_UNSAVEABLE			(0x180UL)
#నిర్వచించు CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#నిర్వచించు CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#నిర్వచించు CKR_MUTEX_BAD				(0x1a0UL)
#నిర్వచించు CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#నిర్వచించు CKR_FUNCTION_REJECTED			(0x200UL)
#నిర్వచించు CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#నిర్వచితమైతే CRYPTOKI_COMPAT

#నిర్వచనం_రద్దు CK_DEFINE_FUNCTION
#నిర్వచించు CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#అన్తర్భావ <stddef.h>

రకనిర్వచనం గుర్తులేని అక్షరం CK_BYTE;
రకనిర్వచనం గుర్తులేని అక్షరం CK_CHAR;
రకనిర్వచనం గుర్తులేని అక్షరం CK_UTF8CHAR;
రకనిర్వచనం గుర్తులేని అక్షరం CK_BBOOL;
రకనిర్వచనం గుర్తులేని దీర్ఘ పూర్ణాంకం CK_ULONG;
రకనిర్వచనం దీర్ఘ పూర్ణాంకం CK_LONG;
రకనిర్వచనం CK_BYTE *CK_BYTE_PTR;
రకనిర్వచనం CK_CHAR *CK_CHAR_PTR;
రకనిర్వచనం CK_UTF8CHAR *CK_UTF8CHAR_PTR;
రకనిర్వచనం CK_ULONG *CK_ULONG_PTR;
రకనిర్వచనం శూన్య *CK_VOID_PTR;
రకనిర్వచనం శూన్య **CK_VOID_PTR_PTR;
#నిర్వచించు CK_FALSE 0
#నిర్వచించు CK_TRUE 1
#నిర్వచితం_కాకపోతే CK_DISABLE_TRUE_FALSE
#నిర్వచితం_కాకపోతే FALSE
#నిర్వచించు FALSE 0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే TRUE
#నిర్వచించు TRUE 1
#అయితే_ముగింపు
#అయితే_ముగింపు

రకనిర్వచనం నిర్మాణం CK_HKDF_PARAMS {
	CK_BBOOL b_వెలికితీయి;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_కీలకం;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#నిర్వచించు CKF_HKDF_SALT_NULL 0x00000001UL
#నిర్వచించు CKF_HKDF_SALT_దత్తాంశం 0x00000002UL
#నిర్వచించు CKF_HKDF_SALT_కీలకం  0x00000004UL

రకనిర్వచనం నిర్మాణం ck_సంస్కరణ CK_సంస్కరణ_2;
రకనిర్వచనం నిర్మాణం ck_సంస్కరణ *CK_సంస్కరణ_PTR;

రకనిర్వచనం నిర్మాణం ck_info CK_INFO;
రకనిర్వచనం నిర్మాణం ck_info *CK_INFO_PTR;

రకనిర్వచనం ck_స్థానం_id_t *CK_స్థానం_ID_PTR;

రకనిర్వచనం నిర్మాణం ck_స్థానం_info CK_స్థానం_INFO_2;
రకనిర్వచనం నిర్మాణం ck_స్థానం_info *CK_స్థానం_INFO_PTR;

రకనిర్వచనం నిర్మాణం ck_token_info CK_TOKEN_INFO;
రకనిర్వచనం నిర్మాణం ck_token_info *CK_TOKEN_INFO_PTR;

రకనిర్వచనం ck_session_handle_t *CK_SESSION_HANDLE_PTR;

రకనిర్వచనం నిర్మాణం ck_session_info CK_SESSION_INFO;
రకనిర్వచనం నిర్మాణం ck_session_info *CK_SESSION_INFO_PTR;

రకనిర్వచనం ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

రకనిర్వచనం ck_object_class_t *CK_OBJECT_CLASS_PTR;

రకనిర్వచనం నిర్మాణం ck_attribute CK_ATTRIBUTE;
రకనిర్వచనం నిర్మాణం ck_attribute *CK_ATTRIBUTE_PTR;

రకనిర్వచనం నిర్మాణం ck_date CK_DATE;
రకనిర్వచనం నిర్మాణం ck_date *CK_DATE_PTR;

రకనిర్వచనం ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

రకనిర్వచనం ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

రకనిర్వచనం నిర్మాణం ck_mechanism CK_MECHANISM;
రకనిర్వచనం నిర్మాణం ck_mechanism *CK_MECHANISM_PTR;

రకనిర్వచనం నిర్మాణం ck_mechanism_info CK_MECHANISM_INFO;
రకనిర్వచనం నిర్మాణం ck_mechanism_info *CK_MECHANISM_INFO_PTR;

రకనిర్వచనం నిర్మాణం ck_interface CK_INTERFACE;
రకనిర్వచనం నిర్మాణం ck_interface *CK_INTERFACE_PTR;
రకనిర్వచనం నిర్మాణం ck_interface **CK_INTERFACE_PTR_PTR;

రకనిర్వచనం నిర్మాణం ck_function_list CK_FUNCTION_LIST;
రకనిర్వచనం నిర్మాణం ck_function_list *CK_FUNCTION_LIST_PTR;
రకనిర్వచనం నిర్మాణం ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

రకనిర్వచనం నిర్మాణం ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
రకనిర్వచనం నిర్మాణం ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
రకనిర్వచనం నిర్మాణం ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

రకనిర్వచనం నిర్మాణం ck_c_initialize_వాదనలు CK_C_INITIALIZE_వాదనలు_2;
రకనిర్వచనం నిర్మాణం ck_c_initialize_వాదనలు *CK_C_INITIALIZE_వాదనలు_PTR;

#నిర్వచించు NULL_PTR ఖాళీ

/* Delete the helper macros defined at the top of the file.  */
#నిర్వచనం_రద్దు ck_flags_t
#నిర్వచనం_రద్దు ck_సంస్కరణ

#నిర్వచనం_రద్దు ck_info
#నిర్వచనం_రద్దు cryptoki_సంస్కరణ
#నిర్వచనం_రద్దు manufacturer_id
#నిర్వచనం_రద్దు library_description
#నిర్వచనం_రద్దు library_సంస్కరణ

#నిర్వచనం_రద్దు ck_notification_t
#నిర్వచనం_రద్దు ck_స్థానం_id_t

#నిర్వచనం_రద్దు ck_స్థానం_info
#నిర్వచనం_రద్దు స్థానం_description
#నిర్వచనం_రద్దు hardware_సంస్కరణ
#నిర్వచనం_రద్దు firmware_సంస్కరణ

#నిర్వచనం_రద్దు ck_token_info
#నిర్వచనం_రద్దు serial_సంఖ్య
#నిర్వచనం_రద్దు max_session_లెక్క
#నిర్వచనం_రద్దు session_లెక్క
#నిర్వచనం_రద్దు max_rw_session_లెక్క
#నిర్వచనం_రద్దు rw_session_లెక్క
#నిర్వచనం_రద్దు max_pin_len
#నిర్వచనం_రద్దు min_pin_len
#నిర్వచనం_రద్దు మొత్తం_ప్రజా_జ్ఞాపకం
#నిర్వచనం_రద్దు free_ప్రజా_జ్ఞాపకం
#నిర్వచనం_రద్దు మొత్తం_వ్యక్తిగత_జ్ఞాపకం
#నిర్వచనం_రద్దు free_వ్యక్తిగత_జ్ఞాపకం
#నిర్వచనం_రద్దు utc_సమయం

#నిర్వచనం_రద్దు ck_session_handle_t
#నిర్వచనం_రద్దు ck_user_type_t
#నిర్వచనం_రద్దు ck_state_t

#నిర్వచనం_రద్దు ck_session_info
#నిర్వచనం_రద్దు స్థానం_id
#నిర్వచనం_రద్దు device_error

#నిర్వచనం_రద్దు ck_object_handle_t
#నిర్వచనం_రద్దు ck_object_class_t
#నిర్వచనం_రద్దు ck_hw_feature_type_t
#నిర్వచనం_రద్దు ck_కీలకం_type_t
#నిర్వచనం_రద్దు ck_certificate_type_t
#నిర్వచనం_రద్దు ck_attribute_type_t

#నిర్వచనం_రద్దు ck_attribute
#నిర్వచనం_రద్దు విలువ
#నిర్వచనం_రద్దు విలువ_len

#నిర్వచనం_రద్దు ck_date

#నిర్వచనం_రద్దు ck_mechanism_type_t

#నిర్వచనం_రద్దు ck_rsa_pkcs_mgf_type_t

#నిర్వచనం_రద్దు ck_mechanism
#నిర్వచనం_రద్దు parameter
#నిర్వచనం_రద్దు parameter_len

#నిర్వచనం_రద్దు ck_mechanism_info
#నిర్వచనం_రద్దు min_కీలకం_కొలత
#నిర్వచనం_రద్దు max_కీలకం_కొలత

#నిర్వచనం_రద్దు ck_rv_t
#నిర్వచనం_రద్దు ck_notify_t

#నిర్వచనం_రద్దు ck_interface

#నిర్వచనం_రద్దు ck_function_list
#నిర్వచనం_రద్దు ck_function_list_3_0

#నిర్వచనం_రద్దు ck_createmutex_t
#నిర్వచనం_రద్దు ck_destroymutex_t
#నిర్వచనం_రద్దు ck_lockmutex_t
#నిర్వచనం_రద్దు ck_unlockmutex_t

#నిర్వచనం_రద్దు ck_c_initialize_వాదనలు
#నిర్వచనం_రద్దు create_mutex
#నిర్వచనం_రద్దు destroy_mutex
#నిర్వచనం_రద్దు తాళం_mutex
#నిర్వచనం_రద్దు unlock_mutex
#నిర్వచనం_రద్దు reserved

#అయితే_ముగింపు	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#ఒకవేళ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#సూచన pack(తీయి, cryptoki)
#అయితే_ముగింపు

#ఒకవేళ defined(__cplusplus)
}
#అయితే_ముగింపు

#అయితే_ముగింపు	/* PKCS11_H */
