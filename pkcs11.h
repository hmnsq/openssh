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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ PKCS11_H
#ವ್ಯಾಖ್ಯಾನಿಸು PKCS11_H 1

#ಆದರೆ defined(__cplusplus)
ಬಾಹ್ಯ "C" {
#ಆದರೆ_ಅಂತ್ಯ


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#ವ್ಯಾಖ್ಯಾನಿಸು CRYPTOKI_ಆವೃತ್ತಿ_MAJOR		3
#ವ್ಯಾಖ್ಯಾನಿಸು CRYPTOKI_ಆವೃತ್ತಿ_MINOR		0
#ವ್ಯಾಖ್ಯಾನಿಸು CRYPTOKI_ಆವೃತ್ತಿ_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CRYPTOKI_GNU
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CRYPTOKI_COMPAT
#ವ್ಯಾಖ್ಯಾನಿಸು CRYPTOKI_COMPAT 1
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

/* System dependencies.  */

#ಆದರೆ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#ಸೂಚನೆ pack(ತಳ್ಳು, cryptoki, 1)

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CRYPTOKI_EXPORTS
#ವ್ಯಾಖ್ಯಾನಿಸು CK_SPEC __declspec(dllexport)
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು CK_SPEC __declspec(dllimport)
#ಆದರೆ_ಅಂತ್ಯ

#ಇಲ್ಲದಿದ್ದರೆ

#ವ್ಯಾಖ್ಯಾನಿಸು CK_SPEC

#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#ವ್ಯಾಖ್ಯಾನಿಸು ck_flags_t CK_FLAGS
#ವ್ಯಾಖ್ಯಾನಿಸು ck_ಆವೃತ್ತಿ CK_ಆವೃತ್ತಿ

#ವ್ಯಾಖ್ಯಾನಿಸು ck_info _CK_INFO
#ವ್ಯಾಖ್ಯಾನಿಸು cryptoki_ಆವೃತ್ತಿ cryptoki_ಆವೃತ್ತಿ_2
#ವ್ಯಾಖ್ಯಾನಿಸು manufacturer_id manufacturerID
#ವ್ಯಾಖ್ಯಾನಿಸು library_description libraryDescription
#ವ್ಯಾಖ್ಯಾನಿಸು library_ಆವೃತ್ತಿ library_ಆವೃತ್ತಿ_2

#ವ್ಯಾಖ್ಯಾನಿಸು ck_notification_t CK_NOTIFICATION
#ವ್ಯಾಖ್ಯಾನಿಸು ck_ಸ್ಥಾನ_id_t CK_ಸ್ಥಾನ_ID

#ವ್ಯಾಖ್ಯಾನಿಸು ck_ಸ್ಥಾನ_info CK_ಸ್ಥಾನ_INFO
#ವ್ಯಾಖ್ಯಾನಿಸು ಸ್ಥಾನ_description ಸ್ಥಾನ_Description
#ವ್ಯಾಖ್ಯಾನಿಸು hardware_ಆವೃತ್ತಿ hardware_ಆವೃತ್ತಿ_2
#ವ್ಯಾಖ್ಯಾನಿಸು firmware_ಆವೃತ್ತಿ firmware_ಆವೃತ್ತಿ_2

#ವ್ಯಾಖ್ಯಾನಿಸು ck_token_info _CK_TOKEN_INFO
#ವ್ಯಾಖ್ಯಾನಿಸು serial_ಸಂಖ್ಯೆ serial_ಸಂಖ್ಯೆ_2
#ವ್ಯಾಖ್ಯಾನಿಸು max_session_ಎಣಿಕೆ ul_Max_Session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನಿಸು session_ಎಣಿಕೆ ul_Session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನಿಸು max_rw_session_ಎಣಿಕೆ ul_Max_Rw_Session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನಿಸು rw_session_ಎಣಿಕೆ ul_Rw_Session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನಿಸು max_pin_len ulMaxPinLen
#ವ್ಯಾಖ್ಯಾನಿಸು min_pin_len ulMinPinLen
#ವ್ಯಾಖ್ಯಾನಿಸು ಒಟ್ಟು_ಬಹಿರಂಗ_ಸ್ಮರಣೆ ul_ಒಟ್ಟು_ಬಹಿರಂಗ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನಿಸು free_ಬಹಿರಂಗ_ಸ್ಮರಣೆ ul_Free_ಬಹಿರಂಗ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನಿಸು ಒಟ್ಟು_ಖಾಸಗಿ_ಸ್ಮರಣೆ ul_ಒಟ್ಟು_ಖಾಸಗಿ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನಿಸು free_ಖಾಸಗಿ_ಸ್ಮರಣೆ ul_Free_ಖಾಸಗಿ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನಿಸು utc_ಸಮಯ utc_ಸಮಯ_2

#ವ್ಯಾಖ್ಯಾನಿಸು ck_session_handle_t CK_SESSION_HANDLE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_user_type_t CK_USER_TYPE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_state_t CK_STATE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_session_info _CK_SESSION_INFO
#ವ್ಯಾಖ್ಯಾನಿಸು ಸ್ಥಾನ_id ಸ್ಥಾನ_ID
#ವ್ಯಾಖ್ಯಾನಿಸು device_error ulDeviceError

#ವ್ಯಾಖ್ಯಾನಿಸು ck_object_handle_t CK_OBJECT_HANDLE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_object_class_t CK_OBJECT_CLASS
#ವ್ಯಾಖ್ಯಾನಿಸು ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_ಕೀಲಿ_type_t CK_ಕೀಲಿ_TYPE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_certificate_type_t CK_CERTIFICATE_TYPE
#ವ್ಯಾಖ್ಯಾನಿಸು ck_attribute_type_t CK_ATTRIBUTE_TYPE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_attribute _CK_ATTRIBUTE
#ವ್ಯಾಖ್ಯಾನಿಸು ಮೌಲ್ಯ p_ಮೌಲ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು ಮೌಲ್ಯ_len ul_ಮೌಲ್ಯ_Len

#ವ್ಯಾಖ್ಯಾನಿಸು ck_date _CK_DATE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_mechanism_type_t CK_MECHANISM_TYPE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_mechanism _CK_MECHANISM
#ವ್ಯಾಖ್ಯಾನಿಸು parameter pParameter
#ವ್ಯಾಖ್ಯಾನಿಸು parameter_len ulParameterLen

#ವ್ಯಾಖ್ಯಾನಿಸು ck_mechanism_info _CK_MECHANISM_INFO
#ವ್ಯಾಖ್ಯಾನಿಸು min_ಕೀಲಿ_ಗಾತ್ರ ul_Min_ಕೀಲಿ_ಗಾತ್ರ
#ವ್ಯಾಖ್ಯಾನಿಸು max_ಕೀಲಿ_ಗಾತ್ರ ul_Max_ಕೀಲಿ_ಗಾತ್ರ

#ವ್ಯಾಖ್ಯಾನಿಸು ck_rv_t CK_RV
#ವ್ಯಾಖ್ಯಾನಿಸು ck_notify_t CK_NOTIFY

#ವ್ಯಾಖ್ಯಾನಿಸು ck_interface CK_INTERFACE

#ವ್ಯಾಖ್ಯಾನಿಸು ck_function_list _CK_FUNCTION_LIST
#ವ್ಯಾಖ್ಯಾನಿಸು ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#ವ್ಯಾಖ್ಯಾನಿಸು ck_createmutex_t CK_CREATEMUTEX
#ವ್ಯಾಖ್ಯಾನಿಸು ck_destroymutex_t CK_DESTROYMUTEX
#ವ್ಯಾಖ್ಯಾನಿಸು ck_lockmutex_t CK_LOCKMUTEX
#ವ್ಯಾಖ್ಯಾನಿಸು ck_unlockmutex_t CK_UNLOCKMUTEX

#ವ್ಯಾಖ್ಯಾನಿಸು ck_c_initialize_ವಾದಗಳು CK_C_INITIALIZE_ವಾದಗಳು
#ವ್ಯಾಖ್ಯಾನಿಸು create_mutex CreateMutex
#ವ್ಯಾಖ್ಯಾನಿಸು destroy_mutex DestroyMutex
#ವ್ಯಾಖ್ಯಾನಿಸು ಬೀಗ_mutex ಬೀಗ_Mutex
#ವ್ಯಾಖ್ಯಾನಿಸು unlock_mutex UnlockMutex
#ವ್ಯಾಖ್ಯಾನಿಸು reserved pReserved

#ಆದರೆ_ಅಂತ್ಯ	/* CRYPTOKI_COMPAT */


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_flags_t;

ರಚನೆ ck_ಆವೃತ್ತಿ
{
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ major;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ minor;
};


ರಚನೆ ck_info
{
  ರಚನೆ ck_ಆವೃತ್ತಿ cryptoki_ಆವೃತ್ತಿ;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ manufacturer_id[32];
  ck_flags_t flags;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ library_description[32];
  ರಚನೆ ck_ಆವೃತ್ತಿ library_ಆವೃತ್ತಿ;
};


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_notification_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKN_SURRENDER	(0UL)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_ಸ್ಥಾನ_id_t;


ರಚನೆ ck_ಸ್ಥಾನ_info
{
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ ಸ್ಥಾನ_description[64];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ manufacturer_id[32];
  ck_flags_t flags;
  ರಚನೆ ck_ಆವೃತ್ತಿ hardware_ಆವೃತ್ತಿ;
  ರಚನೆ ck_ಆವೃತ್ತಿ firmware_ಆವೃತ್ತಿ;
};


#ವ್ಯಾಖ್ಯಾನಿಸು CKF_TOKEN_PRESENT	(1UL << 0)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_REMOVABLE_DEVICE	(1UL << 1)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_HW_ಸ್ಥಾನ		(1UL << 2)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ARRAY_ATTRIBUTE	(1UL << 30)


ರಚನೆ ck_token_info
{
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ label[32];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ manufacturer_id[32];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ model[16];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ serial_ಸಂಖ್ಯೆ[16];
  ck_flags_t flags;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ max_session_ಎಣಿಕೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ session_ಎಣಿಕೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ max_rw_session_ಎಣಿಕೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ rw_session_ಎಣಿಕೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ max_pin_len;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ min_pin_len;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಒಟ್ಟು_ಬಹಿರಂಗ_ಸ್ಮರಣೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ free_ಬಹಿರಂಗ_ಸ್ಮರಣೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಒಟ್ಟು_ಖಾಸಗಿ_ಸ್ಮರಣೆ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ free_ಖಾಸಗಿ_ಸ್ಮರಣೆ;
  ರಚನೆ ck_ಆವೃತ್ತಿ hardware_ಆವೃತ್ತಿ;
  ರಚನೆ ck_ಆವೃತ್ತಿ firmware_ಆವೃತ್ತಿ;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ utc_ಸಮಯ[16];
};


#ವ್ಯಾಖ್ಯಾನಿಸು CKF_RNG					(1UL << 0)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_WRITE_PROTECTED			(1UL << 1)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_LOGIN_REQUIRED			(1UL << 2)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_USER_PIN_INITIALIZED		(1UL << 3)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_RESTORE_ಕೀಲಿ_NOT_NEEDED		(1UL << 5)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_CLOCK_ON_TOKEN			(1UL << 6)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_PROTECTED_AUTHENTICATION_ಮಾರ್ಗ	(1UL << 8)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_TOKEN_INITIALIZED			(1UL << 10)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_USER_PIN_ಎಣಿಕೆ_ಕೆಳಗಿನ			(1UL << 16)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_USER_PIN_LOCKED			(1UL << 18)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_USER_PIN_ಗಮ್ಯ_BE_ಬದಲಾಯಿತು		(1UL << 19)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SO_PIN_ಎಣಿಕೆ_ಕೆಳಗಿನ			(1UL << 20)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SO_PIN_LOCKED			(1UL << 22)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SO_PIN_ಗಮ್ಯ_BE_ಬದಲಾಯಿತು		(1UL << 23)

#ವ್ಯಾಖ್ಯಾನಿಸು CK_UNAVAILABLE_INFORMATION	((ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ) -1)
#ವ್ಯಾಖ್ಯಾನಿಸು CK_EFFECTIVELY_INFINITE		(0UL)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_session_handle_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CK_INVALID_HANDLE	(0UL)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_user_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKU_SO			(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKU_USER		(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKU_CONTEXT_SPECIFIC	(2UL)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_state_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKS_RO_ಬಹಿರಂಗ_SESSION	(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKS_RO_USER_FUNCTIONS	(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKS_RW_ಬಹಿರಂಗ_SESSION	(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKS_RW_USER_FUNCTIONS	(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKS_RW_SO_FUNCTIONS	(4UL)


ರಚನೆ ck_session_info
{
  ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id;
  ck_state_t state;
  ck_flags_t flags;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ device_error;
};

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_RW_SESSION		(1UL << 1)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SERIAL_SESSION	(1UL << 2)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_object_handle_t;


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_object_class_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKO_ದತ್ತಾಂಶ		(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_CERTIFICATE		(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_ಬಹಿರಂಗ_ಕೀಲಿ		(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_ಖಾಸಗಿ_ಕೀಲಿ		(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_SECRET_ಕೀಲಿ		(4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_HW_FEATURE		(5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_DOMAIN_PARAMETERS	(6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_MECHANISM		(7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_OTP_ಕೀಲಿ		(8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_PROFILE		(9UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKO_VENDOR_DEFINED	(1UL << 31)

#ವ್ಯಾಖ್ಯಾನಿಸು CKP_INVALID_ID                (0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKP_BASELINE_PROVIDER         (1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKP_EXTENDED_PROVIDER         (2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKP_AUTHENTICATION_TOKEN      (3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKP_ಬಹಿರಂಗ_CERTIFICATES_TOKEN (4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKP_VENDOR_DEFINED            (1UL << 31)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_hw_feature_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKH_MONOTONIC_COUNTER	(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKH_CLOCK		(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKH_USER_INTERFACE	(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKH_VENDOR_DEFINED	(1UL << 31)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_ಕೀಲಿ_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKK_RSA			(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_DSA			(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_DH			(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_ECDSA		(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_EC			(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_X9_42_DH		(4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_KEA			(5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_GENERIC_SECRET	(0x10UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_RC2			(0x11UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_RC4			(0x12UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_DES			(0x13UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_DES2		(0x14UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_DES3		(0x15UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_CAST		(0x16UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_CAST3		(0x17UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_CAST128		(0x18UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_RC5			(0x19UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_IDEA		(0x1aUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_SKIPJACK		(0x1bUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_BATON		(0x1cUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_JUNIPER		(0x1dUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_CDMF		(0x1eUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_AES			(0x1fUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_BLOWFISH		(0x20UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_TWOFISH		(0x21UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_GOSTR3410		(0x30UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_GOSTR3411		(0x31UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_GOST28147		(0x32UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_EC_EDWARDS		(0x40UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_EC_MONTGOMERY	(0x41UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_HKDF		(0x42UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#ವ್ಯಾಖ್ಯಾನಿಸು NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#ವ್ಯಾಖ್ಯಾನಿಸು CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#ವ್ಯಾಖ್ಯಾನಿಸು CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_certificate_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKC_X_509		(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKC_X_509_ATTR_CERT	(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKC_WTLS		(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKC_VENDOR_DEFINED	(1UL << 31)


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_attribute_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CLASS			(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_TOKEN			(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಖಾಸಗಿ			(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_LABEL			(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_UNIQUE_ID		(4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_APPLICATION			(0x10UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಮೌಲ್ಯ			(0x11UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OBJECT_ID			(0x12UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CERTIFICATE_TYPE		(0x80UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ISSUER			(0x81UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SERIAL_ಸಂಖ್ಯೆ		(0x82UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_AC_ISSUER			(0x83UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OWNER			(0x84UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ATTR_TYPES			(0x85UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_TRUSTED			(0x86UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CERTIFICATE_CATEGORY	(0x87UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_URL				(0x89UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_HASH_ದ_SUBJECT_ಬಹಿರಂಗ_ಕೀಲಿ	(0x8aUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_HASH_ದ_ISSUER_ಬಹಿರಂಗ_ಕೀಲಿ	(0x8bUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CHECK_ಮೌಲ್ಯ			(0x90UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಕೀಲಿ_TYPE			(0x100UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SUBJECT			(0x101UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ID				(0x102UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SENSITIVE			(0x103UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ENCRYPT			(0x104UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_DECRYPT			(0x105UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_WRAP			(0x106UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_UNWRAP			(0x107UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SIGN			(0x108UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SIGN_RECOVER		(0x109UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_VERIFY			(0x10aUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_VERIFY_RECOVER		(0x10bUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_DERIVE			(0x10cUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಆರಂಭ_DATE			(0x110UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಕೊನೆ_DATE			(0x111UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_MODULUS			(0x120UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_MODULUS_ಬಿಟ್ಟುಗಳು		(0x121UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಬಹಿರಂಗ_EXPONENT		(0x122UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಖಾಸಗಿ_EXPONENT		(0x123UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಅವಿಭಾಜ್ಯ_1			(0x124UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಅವಿಭಾಜ್ಯ_2			(0x125UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_EXPONENT_1			(0x126UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_EXPONENT_2			(0x127UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_COEFFICIENT			(0x128UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಬಹಿರಂಗ_ಕೀಲಿ_INFO		(0x129UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಅವಿಭಾಜ್ಯ			(0x130UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SUBPRIME			(0x131UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ತಳ			(0x132UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಅವಿಭಾಜ್ಯ_ಬಿಟ್ಟುಗಳು			(0x133UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SUB_ಅವಿಭಾಜ್ಯ_ಬಿಟ್ಟುಗಳು		(0x134UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಮೌಲ್ಯ_ಬಿಟ್ಟುಗಳು			(0x160UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಮೌಲ್ಯ_LEN			(0x161UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_EXTRACTABLE			(0x162UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_LOCAL			(0x163UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_NEVER_EXTRACTABLE		(0x164UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ALWAYS_SENSITIVE		(0x165UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಕೀಲಿ_GEN_MECHANISM		(0x166UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_MODIFIABLE			(0x170UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_COPYABLE			(0x171UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_DESTROYABLE			(0x172UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ECDSA_PARAMS		(0x180UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_EC_PARAMS			(0x180UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_EC_ಬಿಂದು			(0x181UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SECONDARY_AUTH		(0x200UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_AUTH_PIN_FLAGS		(0x201UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_WRAP_WITH_TRUSTED		(0x210UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_GOSTR3410_PARAMS		(0x250UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_GOSTR3411_PARAMS		(0x251UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_GOST28147_PARAMS		(0x252UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_HW_FEATURE_TYPE		(0x300UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_RESET_ON_INIT		(0x301UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_HAS_RESET			(0x302UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_PIXEL_X			(0x400UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_PIXEL_Y			(0x401UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_RESOLUTION			(0x402UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CHAR_ಅಡ್ಡಸಾಲುಗಳು			(0x403UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CHAR_COLUMNS		(0x404UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_COLOR			(0x405UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ಬಿಟ್ಟುಗಳು_ಪ್ರತಿ_PIXEL		(0x406UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_CHAR_SETS			(0x480UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ENCODING_METHODS		(0x481UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_MIME_TYPES			(0x482UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_MECHANISM_TYPE		(0x500UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_REQUIRED_CMS_ಗುಣಲಕ್ಷಣಗಳು	(0x501UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_DEFAULT_CMS_ಗುಣಲಕ್ಷಣಗಳು	(0x502UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_SUPPORTED_CMS_ಗುಣಲಕ್ಷಣಗಳು	(0x503UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_FORMAT			(0x220UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_ಉದ್ದಳತೆ			(0x221UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_ಸಮಯ_INTERVAL		(0x222UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_USER_FRIENDLY_ಬಹುಲಕ	(0x223UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_ಸಮಯ_REQUIREMENT	(0x225UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_SERVICE_LOGO		(0x22CUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_COUNTER			(0x22EUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_OTP_ಸಮಯ			(0x22FUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_PROFILE_ID			(0x601UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKA_VENDOR_DEFINED		(1UL << 31)


ರಚನೆ ck_attribute
{
  ck_attribute_type_t type;
  ಶೂನ್ಯ *ಮೌಲ್ಯ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಮೌಲ್ಯ_len;
};


ರಚನೆ ck_date
{
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ year[4];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ month[2];
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ day[2];
};


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_mechanism_type_t;

#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_PKCS_ಕೀಲಿ_PAIR_GEN	(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_PKCS			(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_9796			(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_X_509			(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD2_RSA_PKCS		(4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD5_RSA_PKCS		(5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA1_RSA_PKCS		(6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD128_RSA_PKCS		(7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD160_RSA_PKCS		(8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_PKCS_OAEP		(9UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_X9_31_ಕೀಲಿ_PAIR_GEN	(0xaUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_X9_31			(0xbUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA1_RSA_X9_31		(0xcUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RSA_PKCS_PSS		(0xdUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_ಕೀಲಿ_PAIR_GEN		(0x10UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_DSA				(0x11UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_SHA1			(0x12UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_SHA224			(0x13UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_SHA256			(0x14UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_SHA384			(0x15UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_SHA512			(0x16UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DH_PKCS_ಕೀಲಿ_PAIR_GEN	(0x20UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DH_PKCS_DERIVE		(0x21UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_X9_42_DH_ಕೀಲಿ_PAIR_GEN	(0x30UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_X9_42_DH_DERIVE		(0x31UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_X9_42_MQV_DERIVE		(0x33UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA256_RSA_PKCS		(0x40UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA384_RSA_PKCS		(0x41UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA512_RSA_PKCS		(0x42UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA224_RSA_PKCS		(0x46UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256_RSA_PKCS		(0x60UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384_RSA_PKCS		(0x61UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512_RSA_PKCS		(0x62UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224_RSA_PKCS		(0x66UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC2_ಕೀಲಿ_GEN			(0x100UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC2_ECB			(0x101UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_RC2_CBC			(0x102UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_RC2_MAC			(0x103UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC2_MAC_GENERAL		(0x104UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC2_CBC_PAD			(0x105UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC4_ಕೀಲಿ_GEN			(0x110UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC4				(0x111UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_ಕೀಲಿ_GEN			(0x120UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_ECB			(0x121UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_CBC			(0x122UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_MAC			(0x123UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_MAC_GENERAL		(0x124UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_CBC_PAD			(0x125UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES2_ಕೀಲಿ_GEN		(0x130UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_ಕೀಲಿ_GEN		(0x131UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_ECB			(0x132UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_CBC			(0x133UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_MAC			(0x134UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_MAC_GENERAL		(0x135UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_CBC_PAD		(0x136UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_CMAC_GENERAL		(0x137UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_CMAC			(0x138UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_ಕೀಲಿ_GEN		(0x140UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_ECB			(0x141UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_CBC			(0x142UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_MAC			(0x143UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_MAC_GENERAL		(0x144UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CDMF_CBC_PAD		(0x145UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD2				(0x200UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD2_HMAC			(0x201UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD2_HMAC_GENERAL		(0x202UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD5				(0x210UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD5_HMAC			(0x211UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD5_HMAC_GENERAL		(0x212UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA_1			(0x220UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA_1_HMAC			(0x221UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD128			(0x230UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD128_HMAC		(0x231UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD160			(0x240UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD160_HMAC		(0x241UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA256			(0x250UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA256_HMAC			(0x251UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA256_HMAC_GENERAL		(0x252UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA224			(0x255UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA224_HMAC			(0x256UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA224_HMAC_GENERAL		(0x257UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA384			(0x260UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA384_HMAC			(0x261UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA384_HMAC_GENERAL		(0x262UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA512			(0x270UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA512_HMAC			(0x271UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA512_HMAC_GENERAL		(0x272UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256			(0x2B0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256_HMAC		(0x2B1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_256_ಕೀಲಿ_GEN		(0x2B3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224			(0x2B5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224_HMAC		(0x2B6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_224_ಕೀಲಿ_GEN		(0x2B8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384			(0x2C0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384_HMAC		(0x2C1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_384_ಕೀಲಿ_GEN		(0x2C3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512			(0x2D0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512_HMAC		(0x2D1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA3_512_ಕೀಲಿ_GEN		(0x2D3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_ಕೀಲಿ_GEN		(0x300UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_ECB			(0x301UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_CBC			(0x302UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_MAC			(0x303UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_MAC_GENERAL		(0x304UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST_CBC_PAD		(0x305UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_ಕೀಲಿ_GEN		(0x310UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_ECB			(0x311UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_CBC			(0x312UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_MAC			(0x313UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_MAC_GENERAL		(0x314UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST3_CBC_PAD		(0x315UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_ಕೀಲಿ_GEN		(0x320UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST128_ಕೀಲಿ_GEN		(0x320UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_ECB			(0x321UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST128_ECB			(0x321UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_CBC			(0x322UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST128_CBC			(0x322UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_MAC			(0x323UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_CAST128_MAC			(0x323UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_MAC_GENERAL		(0x324UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST128_MAC_GENERAL		(0x324UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST5_CBC_PAD		(0x325UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CAST128_CBC_PAD		(0x325UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_ಕೀಲಿ_GEN			(0x330UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_ECB			(0x331UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_CBC			(0x332UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_MAC			(0x333UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_MAC_GENERAL		(0x334UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_RC5_CBC_PAD			(0x335UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_IDEA_ಕೀಲಿ_GEN		(0x340UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_IDEA_ECB			(0x341UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKM_IDEA_CBC			(0x342UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_IDEA_MAC			(0x343UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_IDEA_MAC_GENERAL		(0x344UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_IDEA_CBC_PAD		(0x345UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GENERIC_SECRET_ಕೀಲಿ_GEN	(0x350UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CONCATENATE_ತಳ_AND_ಕೀಲಿ	(0x360UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CONCATENATE_ತಳ_AND_ದತ್ತಾಂಶ	(0x362UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_CONCATENATE_ದತ್ತಾಂಶ_AND_ತಳ	(0x363UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_XOR_ತಳ_AND_ದತ್ತಾಂಶ		(0x364UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ಹೊರತೆಗೆ_ಕೀಲಿ_FROM_ಕೀಲಿ	(0x365UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_PRE_MASTER_ಕೀಲಿ_GEN	(0x370UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_MASTER_ಕೀಲಿ_DERIVE	(0x371UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_ಕೀಲಿ_AND_MAC_DERIVE	(0x372UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_MASTER_ಕೀಲಿ_DERIVE_DH	(0x373UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TLS_PRE_MASTER_ಕೀಲಿ_GEN	(0x374UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TLS_MASTER_ಕೀಲಿ_DERIVE	(0x375UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TLS_ಕೀಲಿ_AND_MAC_DERIVE	(0x376UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TLS_MASTER_ಕೀಲಿ_DERIVE_DH	(0x377UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_MD5_MAC		(0x380UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SSL3_SHA1_MAC		(0x381UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD5_ಕೀಲಿ_DERIVATION		(0x390UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_MD2_ಕೀಲಿ_DERIVATION		(0x391UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SHA1_ಕೀಲಿ_DERIVATION		(0x392UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PKCS5_PBKD2			(0x3b0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ಕೀಲಿ_WRAP_LYNKS		(0x400UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ಕೀಲಿ_WRAP_ಗಣ_OAEP		(0x401UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_ಕೀಲಿ_GEN		(0x1000UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_ECB64		(0x1001UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_CBC64		(0x1002UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_OFB64		(0x1003UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_CFB64		(0x1004UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_CFB32		(0x1005UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_CFB16		(0x1006UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_CFB8		(0x1007UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_WRAP		(0x1008UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_ಖಾಸಗಿ_WRAP	(0x1009UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_SKIPJACK_RELAYX		(0x100aUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_KEA_ಕೀಲಿ_PAIR_GEN		(0x1010UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_KEA_ಕೀಲಿ_DERIVE		(0x1011UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_ಕೀಲಿ_GEN		(0x1030UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_ECB128		(0x1031UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_ECB96			(0x1032UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_CBC128		(0x1033UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_COUNTER		(0x1034UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_SHUFFLE		(0x1035UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BATON_WRAP			(0x1036UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_ಕೀಲಿ_PAIR_GEN		(0x1040UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_EC_ಕೀಲಿ_PAIR_GEN		(0x1040UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA			(0x1041UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA1			(0x1042UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA224		(0x1043UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA256		(0x1044UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA384		(0x1045UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA512		(0x1046UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA3_224		(0x1047UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA3_256		(0x1048UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA3_384		(0x1049UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDSA_SHA3_512		(0x104AUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDH1_DERIVE		(0x1050UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_ECMQV_DERIVE		(0x1052UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_EC_EDWARDS_ಕೀಲಿ_PAIR_GEN     (0x1055UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_EC_MONTGOMERY_ಕೀಲಿ_PAIR_GEN  (0x1056UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_EDDSA			(0x1057UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_ಕೀಲಿ_GEN		(0x1060UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_ECB128		(0x1061UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_CBC128		(0x1062UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_COUNTER		(0x1063UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_SHUFFLE		(0x1064UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_JUNIPER_WRAP		(0x1065UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_FASTHASH			(0x1070UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_ಕೀಲಿ_GEN			(0x1080UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_ECB			(0x1081UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CBC			(0x1082UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_MAC			(0x1083UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_MAC_GENERAL		(0x1084UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CBC_PAD			(0x1085UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CTR				(0x1086UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_GCM				(0x1087UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CCM				(0x1088UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CTS				(0x1089UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CMAC			(0x108AUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CMAC_GENERAL		(0x108BUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_XCBC_MAC		(0x108CUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_XCBC_MAC_96		(0x108DUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_GMAC			(0x108EUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BLOWFISH_ಕೀಲಿ_GEN    (0x1090UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_BLOWFISH_CBC        (0x1091UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TWOFISH_ಕೀಲಿ_GEN     (0x1092UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_TWOFISH_CBC         (0x1093UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_ECB_ENCRYPT_ದತ್ತಾಂಶ	(0x1100UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES_CBC_ENCRYPT_ದತ್ತಾಂಶ	(0x1101UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_ECB_ENCRYPT_ದತ್ತಾಂಶ	(0x1102UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DES3_CBC_ENCRYPT_ದತ್ತಾಂಶ	(0x1103UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_ECB_ENCRYPT_ದತ್ತಾಂಶ	(0x1104UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CBC_ENCRYPT_ದತ್ತಾಂಶ	(0x1105UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_ಕೀಲಿ_PAIR_GEN	(0x1200UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410			(0x1201UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_ಕೀಲಿ_WRAP  (0x1203UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_DERIVE    (0x1204UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_512_ಕೀಲಿ_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411			(0x1210UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411_HMAC      (0x1211UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOST28147_ಕೀಲಿ_GEN   (0x1220UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOST28147_ECB       (0x1221UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOST28147           (0x1222UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOST28147_MAC       (0x1223UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_GOST28147_ಕೀಲಿ_WRAP  (0x1224UL)

#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DSA_PARAMETER_GEN		(0x2000UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_OFB			(0x2104UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CFB64			(0x2105UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CFB8			(0x2106UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CFB128			(0x2107UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_CFB1			(0x2108UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_ಕೀಲಿ_WRAP		(0x2109UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_AES_ಕೀಲಿ_WRAP_PAD		(0x210AUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_XEDDSA			(0x4029UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_HKDF_DERIVE			(0x402AUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_HKDF_ದತ್ತಾಂಶ			(0x402BUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKM_HKDF_ಕೀಲಿ_GEN		(0x402CUL)

#ವ್ಯಾಖ್ಯಾನಿಸು CKM_VENDOR_DEFINED		(1UL << 31)

ರಚನೆ ck_mechanism
{
  ck_mechanism_type_t mechanism;
  ಶೂನ್ಯ *parameter;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len;
};


ರಚನೆ ck_mechanism_info
{
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ min_ಕೀಲಿ_ಗಾತ್ರ;
  ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ max_ಕೀಲಿ_ಗಾತ್ರ;
  ck_flags_t flags;
};

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_HW			(1UL << 0)

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಸಂದೇಶ_ENCRYPT	(1UL << 1)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಸಂದೇಶ_DECRYPT	(1UL << 2)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಸಂದೇಶ_SIGN	(1UL << 3)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಸಂದೇಶ_VERIFY	(1UL << 4)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_MULTI_ಸಂದೇಶ	(1UL << 5)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಕಂಡುಹಿಡಿ_OBJECTS	(1UL << 6)

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ENCRYPT		(1UL << 8)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_DECRYPT		(1UL << 9)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_DIGEST		(1UL << 10)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SIGN		(1UL << 11)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_SIGN_RECOVER	(1UL << 12)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_VERIFY		(1UL << 13)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_VERIFY_RECOVER	(1UL << 14)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_GENERATE		(1UL << 15)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_GENERATE_ಕೀಲಿ_PAIR	(1UL << 16)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_WRAP		(1UL << 17)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_UNWRAP		(1UL << 18)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_DERIVE		(1UL << 19)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EXTENSION		(1UL << 31)

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_F_P			(1UL << 20)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_F_2M			(1UL << 21)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_ECPARAMETERS	(1UL << 22)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_OID		(1UL << 23)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_NAMEDCURVE	CKF_EC_OID
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_UNCOMPRESS	(1UL << 24)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_COMPRESS		(1UL << 25)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_DONT_ಖಂಡ				(1UL)

/* Flags for Key derivation */
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_NULL			(0x1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_SHA1_KDF			(0x2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_SHA224_KDF			(0x5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_SHA256_KDF			(0x6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_SHA384_KDF			(0x7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKD_SHA512_KDF			(0x8UL)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_ECDH1_DERIVE_PARAMS {
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ  kdf;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ  ul_Shared_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *  p_Shared_ದತ್ತಾಂಶ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ  ul_ಬಹಿರಂಗ_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *  p_ಬಹಿರಂಗ_ದತ್ತಾಂಶ;
} CK_ECDH1_DERIVE_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_ECMQV_DERIVE_PARAMS {
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ kdf;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_Shared_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ * p_Shared_ದತ್ತಾಂಶ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ಬಹಿರಂಗ_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ * p_ಬಹಿರಂಗ_ದತ್ತಾಂಶ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ಖಾಸಗಿ_ದತ್ತಾಂಶ_Len;
	CK_OBJECT_HANDLE h_ಖಾಸಗಿ_ದತ್ತಾಂಶ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ಬಹಿರಂಗ_ದತ್ತಾಂಶ_Len2;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ * p_ಬಹಿರಂಗ_Data2;
	CK_OBJECT_HANDLE ಬಹಿರಂಗ_ಕೀಲಿ_2;
} CK_ECMQV_DERIVE_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_rsa_pkcs_mgf_type_t;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ CK_RSA_PKCS_OAEP_ಮೂಲ_TYPE;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_ಮೂಲ_TYPE ಮೂಲ;
	ಶೂನ್ಯ *p_ಮೂಲ_ದತ್ತಾಂಶ;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ಮೂಲ_ದತ್ತಾಂಶ_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA1			(0x00000001UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA224		(0x00000005UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA256		(0x00000002UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA384		(0x00000003UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA512		(0x00000004UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA3_224	(0x00000006UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA3_256	(0x00000007UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA3_384	(0x00000008UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKG_MGF1_SHA3_512	(0x00000009UL)

#ವ್ಯಾಖ್ಯಾನಿಸು CKZ_ದತ್ತಾಂಶ_SPECIFIED	(0x00000001UL)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_GCM_PARAMS {
	ಶೂನ್ಯ * pIv;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ulIvLen;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_Iv_ಬಿಟ್ಟುಗಳು;
	ಶೂನ್ಯ * pAAD;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ulAADLen;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ಟ್ಯಾಗ್_ಬಿಟ್ಟುಗಳು;
} CK_GCM_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_CCM_PARAMS {
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pNonce;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ulNonceLen;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pAAD;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ulAADLen;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_EDDSA_PARAMS {
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ phFlag;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_Context_ದತ್ತಾಂಶ_Len;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *p_Context_ದತ್ತಾಂಶ;
} CK_EDDSA_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_XEDDSA_PARAMS {
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ hash;
} CK_XEDDSA_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_AES_CTR_PARAMS {
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ul_Counter_ಬಿಟ್ಟುಗಳು;
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ cb[16];
} CK_AES_CTR_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ CK_MAC_GENERAL_PARAMS;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ck_rv_t;


ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, ಶೂನ್ಯ *application);

ರಚನೆ ck_interface {
  ಅಕ್ಷರ * pInterfaceName;
  ಶೂನ್ಯ * pFunctionList;
  ck_flags_t flags;
};

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_INTERFACE_FORK_ಸುರಕ್ಷಿತ	(0x00000001UL)

/* Forward reference.  */
ರಚನೆ ck_function_list;
ರಚನೆ ck_function_list_3_0;

#ವ್ಯಾಖ್ಯಾನಿಸು _CK_DECLARE_FUNCTION(name, ವಾದಗಳು)	\
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*CK_ ## name) ವಾದಗಳು;		\
ck_rv_t CK_SPEC name ವಾದಗಳು

_CK_DECLARE_FUNCTION (C_Initialize, (ಶೂನ್ಯ *init_ವಾದಗಳು));
_CK_DECLARE_FUNCTION (C_Finalize, (ಶೂನ್ಯ *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (ರಚನೆ ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (ರಚನೆ ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_ಸ್ಥಾನ_List,
		      (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ token_present, ck_ಸ್ಥಾನ_id_t *ಸ್ಥಾನ_list,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_Get_ಸ್ಥಾನ_Info,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id, ರಚನೆ ck_ಸ್ಥಾನ_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id, ರಚನೆ ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_ಸ್ಥಾನ_Event,
		      (ck_flags_t flags, ck_ಸ್ಥಾನ_id_t *ಸ್ಥಾನ, ಶೂನ್ಯ *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id,
		       ck_mechanism_type_t *mechanism_list,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id, ck_mechanism_type_t type,
		       ರಚನೆ ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pin,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ pin_len, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pin,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ pin_len));
_CK_DECLARE_FUNCTION (C_ಗಣ_PIN,
		      (ck_session_handle_t session, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *old_pin,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ old_len, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *new_pin,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id, ck_flags_t flags,
		       ಶೂನ್ಯ *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_ಸ್ಥಾನ_id_t ಸ್ಥಾನ_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *operation_state,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *operation_state_len));
_CK_DECLARE_FUNCTION (C_ಗಣ_Operation_State,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *operation_state,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ operation_state_len,
		       ck_object_handle_t encryption_ಕೀಲಿ,
		       ck_object_handle_t authentication_ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pin, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       ರಚನೆ ck_attribute *templ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_ಗಾತ್ರ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಗಾತ್ರ_2));
_CK_DECLARE_FUNCTION (C_Get_Attribute_ಮೌಲ್ಯ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_ಗಣ_Attribute_ಮೌಲ್ಯ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_ಕಂಡುಹಿಡಿ_Objects_Init,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_ಕಂಡುಹಿಡಿ_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ max_object_ಎಣಿಕೆ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *object_ಎಣಿಕೆ));
_CK_DECLARE_FUNCTION (C_ಕಂಡುಹಿಡಿ_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *encrypted_ದತ್ತಾಂಶ_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಕೊನೆಯ_encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಕೊನೆಯ_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ encrypted_ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ದತ್ತಾಂಶ_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ encrypted_part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಕೊನೆಯ_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಕೊನೆಯ_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *digest,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len));
_CK_DECLARE_FUNCTION (C_Digest_ಕೀಲಿ,
		      (ck_session_handle_t session, ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *digest,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ signature_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ದತ್ತಾಂಶ_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ encrypted_part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *encrypted_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ encrypted_part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *part_len));

_CK_DECLARE_FUNCTION (C_Generate_ಕೀಲಿ,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಎಣಿಕೆ_2,
		       ck_object_handle_t *ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Generate_ಕೀಲಿ_Pair,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ರಚನೆ ck_attribute *ಬಹಿರಂಗ_ಕೀಲಿ_template,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಬಹಿರಂಗ_ಕೀಲಿ_attribute_ಎಣಿಕೆ,
		       ರಚನೆ ck_attribute *ಖಾಸಗಿ_ಕೀಲಿ_template,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಖಾಸಗಿ_ಕೀಲಿ_attribute_ಎಣಿಕೆ,
		       ck_object_handle_t *ಬಹಿರಂಗ_ಕೀಲಿ,
		       ck_object_handle_t *ಖಾಸಗಿ_ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Wrap_ಕೀಲಿ,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_ಕೀಲಿ,
		       ck_object_handle_t ಕೀಲಿ,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *wrapped_ಕೀಲಿ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *wrapped_ಕೀಲಿ_len));
_CK_DECLARE_FUNCTION (C_Unwrap_ಕೀಲಿ,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_ಕೀಲಿ,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *wrapped_ಕೀಲಿ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ wrapped_ಕೀಲಿ_len,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ attribute_ಎಣಿಕೆ,
		       ck_object_handle_t *ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Derive_ಕೀಲಿ,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ತಳ_ಕೀಲಿ,
		       ರಚನೆ ck_attribute *templ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ attribute_ಎಣಿಕೆ,
		       ck_object_handle_t *ಕೀಲಿ));

_CK_DECLARE_FUNCTION (C_ಬೀಜ_Random,
		      (ck_session_handle_t session, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಬೀಜ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಬೀಜ_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *random_data,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_ಸ್ಥಿತಿ, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (ರಚನೆ ck_interface *interfaces_list,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ಎಣಿಕೆ_2));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *interface_name,
		       ರಚನೆ ck_ಆವೃತ್ತಿ *ಆವೃತ್ತಿ,
		       ರಚನೆ ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pin,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ pin_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *username,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Encrypt_Init,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Encrypt_ಸಂದೇಶ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *associated_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ associated_ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *plaintext,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ plaintext_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ciphertext,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_ಸಂದೇಶ_Begin,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *associated_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ associated_ದತ್ತಾಂಶ_len));
_CK_DECLARE_FUNCTION (C_Encrypt_ಸಂದೇಶ_ಮುಂದಿನ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *plaintext_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ plaintext_part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ciphertext_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Decrypt_Init,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Decrypt_ಸಂದೇಶ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *associated_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ associated_ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ciphertext,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ciphertext_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *plaintext,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_ಸಂದೇಶ_Begin,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *associated_ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ associated_ದತ್ತಾಂಶ_len));
_CK_DECLARE_FUNCTION (C_Decrypt_ಸಂದೇಶ_ಮುಂದಿನ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ciphertext_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ciphertext_part_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *plaintext_part,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Sign_Init,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Sign_ಸಂದೇಶ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_ಸಂದೇಶ_Begin,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_ಸಂದೇಶ_ಮುಂದಿನ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *signature_len));
_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Verify_Init,
		      (ck_session_handle_t session,
		       ರಚನೆ ck_mechanism *mechanism,
		       ck_object_handle_t ಕೀಲಿ));
_CK_DECLARE_FUNCTION (C_Verify_ಸಂದೇಶ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ signature_len));
_CK_DECLARE_FUNCTION (C_Verify_ಸಂದೇಶ_Begin,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_ಸಂದೇಶ_ಮುಂದಿನ,
		      (ck_session_handle_t session,
		       ಶೂನ್ಯ *parameter,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ parameter_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ದತ್ತಾಂಶ,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದತ್ತಾಂಶ_len,
		       ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *signature,
		       ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ signature_len));
_CK_DECLARE_FUNCTION (C_ಸಂದೇಶ_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_ಕೊನೆ_ದ_ಸಂದೇಶ	(0x00000001UL)

ರಚನೆ ck_function_list
{
  ರಚನೆ ck_ಆವೃತ್ತಿ ಆವೃತ್ತಿ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_ಸ್ಥಾನ_List C_Get_ಸ್ಥಾನ_List;
  CK_C_Get_ಸ್ಥಾನ_Info C_Get_ಸ್ಥಾನ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_ಗಣ_PIN C_ಗಣ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_ಗಣ_Operation_State C_ಗಣ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_ಗಾತ್ರ C_Get_Object_ಗಾತ್ರ;
  CK_C_Get_Attribute_ಮೌಲ್ಯ C_Get_Attribute_ಮೌಲ್ಯ;
  CK_C_ಗಣ_Attribute_ಮೌಲ್ಯ C_ಗಣ_Attribute_ಮೌಲ್ಯ;
  CK_C_ಕಂಡುಹಿಡಿ_Objects_Init C_ಕಂಡುಹಿಡಿ_Objects_Init;
  CK_C_ಕಂಡುಹಿಡಿ_Objects C_ಕಂಡುಹಿಡಿ_Objects;
  CK_C_ಕಂಡುಹಿಡಿ_Objects_Final C_ಕಂಡುಹಿಡಿ_Objects_Final;
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
  CK_C_Digest_ಕೀಲಿ C_Digest_ಕೀಲಿ;
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
  CK_C_Generate_ಕೀಲಿ C_Generate_ಕೀಲಿ;
  CK_C_Generate_ಕೀಲಿ_Pair C_Generate_ಕೀಲಿ_Pair;
  CK_C_Wrap_ಕೀಲಿ C_Wrap_ಕೀಲಿ;
  CK_C_Unwrap_ಕೀಲಿ C_Unwrap_ಕೀಲಿ;
  CK_C_Derive_ಕೀಲಿ C_Derive_ಕೀಲಿ;
  CK_C_ಬೀಜ_Random C_ಬೀಜ_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_ಸ್ಥಿತಿ C_Get_Function_ಸ್ಥಿತಿ;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_ಸ್ಥಾನ_Event C_Wait_For_ಸ್ಥಾನ_Event;
};

ರಚನೆ ck_function_list_3_0
{
  ರಚನೆ ck_ಆವೃತ್ತಿ ಆವೃತ್ತಿ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_ಸ್ಥಾನ_List C_Get_ಸ್ಥಾನ_List;
  CK_C_Get_ಸ್ಥಾನ_Info C_Get_ಸ್ಥಾನ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_ಗಣ_PIN C_ಗಣ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_ಗಣ_Operation_State C_ಗಣ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_ಗಾತ್ರ C_Get_Object_ಗಾತ್ರ;
  CK_C_Get_Attribute_ಮೌಲ್ಯ C_Get_Attribute_ಮೌಲ್ಯ;
  CK_C_ಗಣ_Attribute_ಮೌಲ್ಯ C_ಗಣ_Attribute_ಮೌಲ್ಯ;
  CK_C_ಕಂಡುಹಿಡಿ_Objects_Init C_ಕಂಡುಹಿಡಿ_Objects_Init;
  CK_C_ಕಂಡುಹಿಡಿ_Objects C_ಕಂಡುಹಿಡಿ_Objects;
  CK_C_ಕಂಡುಹಿಡಿ_Objects_Final C_ಕಂಡುಹಿಡಿ_Objects_Final;
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
  CK_C_Digest_ಕೀಲಿ C_Digest_ಕೀಲಿ;
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
  CK_C_Generate_ಕೀಲಿ C_Generate_ಕೀಲಿ;
  CK_C_Generate_ಕೀಲಿ_Pair C_Generate_ಕೀಲಿ_Pair;
  CK_C_Wrap_ಕೀಲಿ C_Wrap_ಕೀಲಿ;
  CK_C_Unwrap_ಕೀಲಿ C_Unwrap_ಕೀಲಿ;
  CK_C_Derive_ಕೀಲಿ C_Derive_ಕೀಲಿ;
  CK_C_ಬೀಜ_Random C_ಬೀಜ_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_ಸ್ಥಿತಿ C_Get_Function_ಸ್ಥಿತಿ;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_ಸ್ಥಾನ_Event C_Wait_For_ಸ್ಥಾನ_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_ಸಂದೇಶ_Encrypt_Init C_ಸಂದೇಶ_Encrypt_Init;
  CK_C_Encrypt_ಸಂದೇಶ C_Encrypt_ಸಂದೇಶ;
  CK_C_Encrypt_ಸಂದೇಶ_Begin C_Encrypt_ಸಂದೇಶ_Begin;
  CK_C_Encrypt_ಸಂದೇಶ_ಮುಂದಿನ C_Encrypt_ಸಂದೇಶ_ಮುಂದಿನ;
  CK_C_ಸಂದೇಶ_Encrypt_Final C_ಸಂದೇಶ_Encrypt_Final;
  CK_C_ಸಂದೇಶ_Decrypt_Init C_ಸಂದೇಶ_Decrypt_Init;
  CK_C_Decrypt_ಸಂದೇಶ C_Decrypt_ಸಂದೇಶ;
  CK_C_Decrypt_ಸಂದೇಶ_Begin C_Decrypt_ಸಂದೇಶ_Begin;
  CK_C_Decrypt_ಸಂದೇಶ_ಮುಂದಿನ C_Decrypt_ಸಂದೇಶ_ಮುಂದಿನ;
  CK_C_ಸಂದೇಶ_Decrypt_Final C_ಸಂದೇಶ_Decrypt_Final;
  CK_C_ಸಂದೇಶ_Sign_Init C_ಸಂದೇಶ_Sign_Init;
  CK_C_Sign_ಸಂದೇಶ C_Sign_ಸಂದೇಶ;
  CK_C_Sign_ಸಂದೇಶ_Begin C_Sign_ಸಂದೇಶ_Begin;
  CK_C_Sign_ಸಂದೇಶ_ಮುಂದಿನ C_Sign_ಸಂದೇಶ_ಮುಂದಿನ;
  CK_C_ಸಂದೇಶ_Sign_Final C_ಸಂದೇಶ_Sign_Final;
  CK_C_ಸಂದೇಶ_Verify_Init C_ಸಂದೇಶ_Verify_Init;
  CK_C_Verify_ಸಂದೇಶ C_Verify_ಸಂದೇಶ;
  CK_C_Verify_ಸಂದೇಶ_Begin C_Verify_ಸಂದೇಶ_Begin;
  CK_C_Verify_ಸಂದೇಶ_ಮುಂದಿನ C_Verify_ಸಂದೇಶ_ಮುಂದಿನ;
  CK_C_ಸಂದೇಶ_Verify_Final C_ಸಂದೇಶ_Verify_Final;
};



ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*ck_createmutex_t) (ಶೂನ್ಯ **mutex);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*ck_destroymutex_t) (ಶೂನ್ಯ *mutex);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*ck_lockmutex_t) (ಶೂನ್ಯ *mutex);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rv_t (*ck_unlockmutex_t) (ಶೂನ್ಯ *mutex);


ರಚನೆ ck_c_initialize_ವಾದಗಳು
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t ಬೀಗ_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  ಶೂನ್ಯ *reserved;
};


#ವ್ಯಾಖ್ಯಾನಿಸು CKF_LIBRARY_CANT_CREATE_OS_ಎಳೆಗಳು	(1UL << 0)
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_OS_LOCKING_OK			(1UL << 1)

#ವ್ಯಾಖ್ಯಾನಿಸು CKR_OK					(0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_CANCEL				(1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_HOST_ಸ್ಮರಣೆ				(2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಸ್ಥಾನ_ID_INVALID			(3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_GENERAL_ERROR			(5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_FUNCTION_FAILED			(6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ARGUMENTS_BAD			(7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_NO_EVENT				(8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_NEED_ಗಮ್ಯ_CREATE_ಎಳೆಗಳು		(9UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_CANT_ಬೀಗ				(0xaUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ATTRIBUTE_ಮೌಲ್ಯ_INVALID		(0x13UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ACTION_PROHIBITED			(0x1BUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ದತ್ತಾಂಶ_INVALID			(0x20UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ದತ್ತಾಂಶ_LEN_RANGE			(0x21UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_DEVICE_ERROR			(0x30UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_DEVICE_ಸ್ಮರಣೆ			(0x31UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_DEVICE_REMOVED			(0x32UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ENCRYPTED_ದತ್ತಾಂಶ_INVALID		(0x40UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ENCRYPTED_ದತ್ತಾಂಶ_LEN_RANGE		(0x41UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_FUNCTION_CANCELED			(0x50UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_HANDLE_INVALID			(0x60UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_ಗಾತ್ರ_RANGE			(0x62UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_TYPE_INCONSISTENT		(0x63UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_NOT_NEEDED			(0x64UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_ಬದಲಾಯಿತು				(0x65UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_NEEDED				(0x66UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_INDIGESTIBLE			(0x67UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_FUNCTION_NOT_PERMITTED		(0x68UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_NOT_WRAPPABLE			(0x69UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಕೀಲಿ_UNEXTRACTABLE			(0x6aUL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_MECHANISM_INVALID			(0x70UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_OPERATION_ಸಕ್ರಿಯ			(0x90UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_PIN_INCORRECT			(0xa0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_PIN_INVALID				(0xa1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_PIN_LEN_RANGE			(0xa2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_PIN_EXPIRED				(0xa3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_PIN_LOCKED				(0xa4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_CLOSED			(0xb0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_ಎಣಿಕೆ			(0xb1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_READ_ONLY			(0xb5UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_EXISTS			(0xb6UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SIGNATURE_INVALID			(0xc0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು	CKR_UNWRAPPING_ಕೀಲಿ_HANDLE_INVALID	(0xf0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_UNWRAPPING_ಕೀಲಿ_ಗಾತ್ರ_RANGE		(0xf1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_UNWRAPPING_ಕೀಲಿ_TYPE_INCONSISTENT	(0xf2UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_ALREADY_LOGGED_ಒಳ		(0x100UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_NOT_LOGGED_ಒಳ			(0x101UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_TYPE_INVALID			(0x103UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_ANOTHER_ALREADY_LOGGED_ಒಳ	(0x104UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_USER_TOO_MANY_TYPES			(0x105UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_WRAPPED_ಕೀಲಿ_INVALID			(0x110UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_WRAPPED_ಕೀಲಿ_LEN_RANGE		(0x112UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_WRAPPING_ಕೀಲಿ_HANDLE_INVALID		(0x113UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_WRAPPING_ಕೀಲಿ_ಗಾತ್ರ_RANGE		(0x114UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_WRAPPING_ಕೀಲಿ_TYPE_INCONSISTENT	(0x115UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_RANDOM_ಬೀಜ_NOT_SUPPORTED		(0x120UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_RANDOM_NO_RNG			(0x121UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ವಕ್ರ_NOT_SUPPORTED			(0x140UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_ಬಫರ್_TOO_SMALL			(0x150UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_SAVED_STATE_INVALID			(0x160UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_INFORMATION_SENSITIVE		(0x170UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_STATE_UNSAVEABLE			(0x180UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_MUTEX_BAD				(0x1a0UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_FUNCTION_REJECTED			(0x200UL)
#ವ್ಯಾಖ್ಯಾನಿಸು CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CRYPTOKI_COMPAT

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CK_DEFINE_FUNCTION
#ವ್ಯಾಖ್ಯಾನಿಸು CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#ಅನ್ತರ್ಭಾವ <stddef.h>

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ CK_BYTE;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ CK_CHAR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ CK_UTF8CHAR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ CK_BBOOL;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ CK_ULONG;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ CK_LONG;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_BYTE *CK_BYTE_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_CHAR *CK_CHAR_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_UTF8CHAR *CK_UTF8CHAR_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ CK_ULONG *CK_ULONG_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ *CK_VOID_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ **CK_VOID_PTR_PTR;
#ವ್ಯಾಖ್ಯಾನಿಸು CK_FALSE 0
#ವ್ಯಾಖ್ಯಾನಿಸು CK_TRUE 1
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CK_DISABLE_TRUE_FALSE
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ FALSE
#ವ್ಯಾಖ್ಯಾನಿಸು FALSE 0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ TRUE
#ವ್ಯಾಖ್ಯಾನಿಸು TRUE 1
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ CK_HKDF_PARAMS {
	CK_BBOOL b_ಹೊರತೆಗೆ;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_ಕೀಲಿ;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#ವ್ಯಾಖ್ಯಾನಿಸು CKF_HKDF_SALT_NULL 0x00000001UL
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_HKDF_SALT_ದತ್ತಾಂಶ 0x00000002UL
#ವ್ಯಾಖ್ಯಾನಿಸು CKF_HKDF_SALT_ಕೀಲಿ  0x00000004UL

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_ಆವೃತ್ತಿ CK_ಆವೃತ್ತಿ_2;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_ಆವೃತ್ತಿ *CK_ಆವೃತ್ತಿ_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_info CK_INFO;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_info *CK_INFO_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_ಸ್ಥಾನ_id_t *CK_ಸ್ಥಾನ_ID_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_ಸ್ಥಾನ_info CK_ಸ್ಥಾನ_INFO_2;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_ಸ್ಥಾನ_info *CK_ಸ್ಥಾನ_INFO_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_token_info CK_TOKEN_INFO;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_token_info *CK_TOKEN_INFO_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_session_handle_t *CK_SESSION_HANDLE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_session_info CK_SESSION_INFO;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_session_info *CK_SESSION_INFO_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_object_class_t *CK_OBJECT_CLASS_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_attribute CK_ATTRIBUTE;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_attribute *CK_ATTRIBUTE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_date CK_DATE;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_date *CK_DATE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_mechanism CK_MECHANISM;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_mechanism *CK_MECHANISM_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_mechanism_info CK_MECHANISM_INFO;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_mechanism_info *CK_MECHANISM_INFO_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_interface CK_INTERFACE;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_interface *CK_INTERFACE_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_interface **CK_INTERFACE_PTR_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list CK_FUNCTION_LIST;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list *CK_FUNCTION_LIST_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_c_initialize_ವಾದಗಳು CK_C_INITIALIZE_ವಾದಗಳು_2;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ck_c_initialize_ವಾದಗಳು *CK_C_INITIALIZE_ವಾದಗಳು_PTR;

#ವ್ಯಾಖ್ಯಾನಿಸು NULL_PTR ಖಾಲಿ

/* Delete the helper macros defined at the top of the file.  */
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_flags_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_ಆವೃತ್ತಿ

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_info
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು cryptoki_ಆವೃತ್ತಿ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು manufacturer_id
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು library_description
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು library_ಆವೃತ್ತಿ

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_notification_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_ಸ್ಥಾನ_id_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_ಸ್ಥಾನ_info
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಸ್ಥಾನ_description
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು hardware_ಆವೃತ್ತಿ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು firmware_ಆವೃತ್ತಿ

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_token_info
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು serial_ಸಂಖ್ಯೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು max_session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು max_rw_session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು rw_session_ಎಣಿಕೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು max_pin_len
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು min_pin_len
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಒಟ್ಟು_ಬಹಿರಂಗ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_ಬಹಿರಂಗ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಒಟ್ಟು_ಖಾಸಗಿ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು free_ಖಾಸಗಿ_ಸ್ಮರಣೆ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು utc_ಸಮಯ

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_session_handle_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_user_type_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_state_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_session_info
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಸ್ಥಾನ_id
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು device_error

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_object_handle_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_object_class_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_hw_feature_type_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_ಕೀಲಿ_type_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_certificate_type_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_attribute_type_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_attribute
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಮೌಲ್ಯ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಮೌಲ್ಯ_len

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_date

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_mechanism_type_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_rsa_pkcs_mgf_type_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_mechanism
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು parameter
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು parameter_len

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_mechanism_info
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು min_ಕೀಲಿ_ಗಾತ್ರ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು max_ಕೀಲಿ_ಗಾತ್ರ

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_rv_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_notify_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_interface

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_function_list
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_function_list_3_0

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_createmutex_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_destroymutex_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_lockmutex_t
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_unlockmutex_t

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ck_c_initialize_ವಾದಗಳು
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು create_mutex
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು destroy_mutex
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ಬೀಗ_mutex
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು unlock_mutex
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು reserved

#ಆದರೆ_ಅಂತ್ಯ	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#ಆದರೆ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#ಸೂಚನೆ pack(ತೆಗೆ, cryptoki)
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(__cplusplus)
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ	/* PKCS11_H */
