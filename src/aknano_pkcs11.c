/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define LIBRARY_LOG_NAME "aktest"
#define LIBRARY_LOG_LEVEL LOG_INFO
#include "logging_stack.h"

#include "aknano_priv.h"

#include "pkcs11t.h"

#include "mbedtls/pem.h"
#include "mbedtls/sha512.h"

#ifdef AKNANO_RESET_DEVICE_ID
CK_RV prvDestroyDefaultCryptoObjects(void)
{
    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle = 0;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t *pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;

    xResult = C_GetFunctionList(&xFunctionList);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_Initialize(NULL);

    if ((CKR_OK == xResult) || (CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult))
        xResult = xFunctionList->C_GetSlotList(CK_TRUE, &xSlotId, &xCount);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_OpenSession(xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession);

    if (CKR_OK == xResult)
        xResult = xDestroyDefaultCryptoObjects(xSession);

    if (xSessionOpen == CK_TRUE)
        (void)xFunctionList->C_CloseSession(xSession);

    return xResult;
}
#endif

#if defined(AKNANO_ENABLE_EXPLICIT_REGISTRATION) || defined(AKNANO_ALLOW_PROVISIONING)
#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

static CK_RV prvGetCertificateHandle(CK_FUNCTION_LIST_PTR pxFunctionList,
                                     CK_SESSION_HANDLE    xSession,
                                     const char *         pcLabelName,
                                     CK_OBJECT_HANDLE_PTR pxCertHandle)
{
    CK_ATTRIBUTE xTemplate;
    CK_RV xResult = CKR_OK;
    CK_ULONG ulCount = 0;
    CK_BBOOL xFindInit = CK_FALSE;

    /* Get the certificate handle. */
    if (0 == xResult) {
        xTemplate.type = CKA_LABEL;
        xTemplate.ulValueLen = strlen(pcLabelName);  // + 1;
        xTemplate.pValue = (char *)pcLabelName;
        xResult = pxFunctionList->C_FindObjectsInit(xSession, &xTemplate, 1);
    }

    if (0 == xResult) {
        xFindInit = CK_TRUE;
        xResult = pxFunctionList->C_FindObjects(xSession,
                                                (CK_OBJECT_HANDLE_PTR)pxCertHandle,
                                                1,
                                                &ulCount);
    }

    if (CK_TRUE == xFindInit)
        xResult = pxFunctionList->C_FindObjectsFinal(xSession);

    return xResult;
}

/* Note that this function mallocs a buffer for the certificate to reside in,
 * and it is the responsibility of the caller to free the buffer. */
static CK_RV prvGetCertificate(const char *pcLabelName,
                               uint8_t **  ppucData,
                               uint32_t *  pulDataSize)
{
    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle = 0;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t *pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;

    xResult = C_GetFunctionList(&xFunctionList);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_Initialize(NULL);

    if ((CKR_OK == xResult) || (CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult))
        xResult = xFunctionList->C_GetSlotList(CK_TRUE, &xSlotId, &xCount);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_OpenSession(xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession);

    if (CKR_OK == xResult) {
        xSessionOpen = CK_TRUE;
        xResult = prvGetCertificateHandle(xFunctionList, xSession, pcLabelName, &xHandle);
    }

    if ((xHandle != 0) && (xResult == CKR_OK)) {    /* 0 is an invalid handle */
        /* Get the length of the certificate */
        xTemplate.type = CKA_VALUE;
        xTemplate.pValue = NULL;
        xResult = xFunctionList->C_GetAttributeValue(xSession, xHandle, &xTemplate, xCount);

        if (xResult == CKR_OK)
            pucCert = pvPortMalloc(xTemplate.ulValueLen);

        if ((xResult == CKR_OK) && (pucCert == NULL))
            xResult = CKR_HOST_MEMORY;

        if (xResult == CKR_OK) {
            xTemplate.pValue = pucCert;
            xResult = xFunctionList->C_GetAttributeValue(xSession, xHandle, &xTemplate, xCount);

            if (xResult == CKR_OK) {
                *ppucData = pucCert;
                *pulDataSize = xTemplate.ulValueLen;
            } else {
                vPortFree(pucCert);
            }
        }
    } else { /* Certificate was not found. */
        *ppucData = NULL;
        *pulDataSize = 0;
    }

    if (xSessionOpen == CK_TRUE)
        (void)xFunctionList->C_CloseSession(xSession);

    return xResult;
}

CK_RV aknano_read_device_certificate(char *dst, size_t dst_size)
{
    uint8_t *cert_data = NULL;
    uint32_t cert_size = 0;
    CK_RV ret = prvGetCertificate(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, &cert_data, &cert_size);

    LogInfo(("aknano_read_device_certificate '" pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS "' ret=%d", ret));
    LogInfo(("aknano_read_device_certificate cert_size=%d", cert_size));
    if (ret == 0 && cert_size > 0) {
        // static char pem_buffer[2048];
        cert_data[cert_size] = 0;
        cert_size++;
        size_t olen;
        ret = mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                       cert_data, cert_size,
                                       (unsigned char *)dst, dst_size, &olen);
        if (ret == 0) {
            LogInfo(("aknano_read_device_certificate pem cert size=%u", olen));
            LogInfo(("aknano_read_device_certificate pem cert:\r\n%s", dst));
        } else {
            LogInfo(("aknano_read_device_certificate pem cert error ret=%d", ret));
        }
    }

    if (cert_data != NULL)
        vPortFree(cert_data);
    return ret;
}
#endif

#ifdef AKNANO_ALLOW_PROVISIONING
/* Perform device provisioning using the default TLS client credentials. */
void vDevModeKeyProvisioning_AkNano(uint8_t *client_key, uint8_t *client_certificate, uint8_t *client_pub_key)
{
    ProvisioningParams_t xParams;

    xParams.pucJITPCertificate = NULL;
    xParams.pucClientPrivateKey = client_key;
    xParams.pucClientCertificate = client_certificate;

    /* If using a JITR flow, a JITR certificate must be supplied. If using credentials generated by
     * AWS, this certificate is not needed. */
    if ((NULL != xParams.pucJITPCertificate) &&
        (0 != strcmp("", (const char *)xParams.pucJITPCertificate)))
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulJITPCertificateLength = sizeof(char) + strlen((const char *)xParams.pucJITPCertificate);
    else
        xParams.pucJITPCertificate = NULL;

    /* The hard-coded client certificate and private key can be useful for
     * first-time lab testing. They are optional after the first run, though, and
     * not recommended at all for going into production. */
    if ((NULL != xParams.pucClientPrivateKey) &&
        (0 != strcmp("", (const char *)xParams.pucClientPrivateKey)))
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientPrivateKeyLength = sizeof(char) + strlen((const char *)xParams.pucClientPrivateKey);
    else
        xParams.pucClientPrivateKey = NULL;

    if ((NULL != xParams.pucClientCertificate) &&
        (0 != strcmp("", (const char *)xParams.pucClientCertificate)))
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientCertificateLength = sizeof(char) + strlen((const char *)xParams.pucClientCertificate);
    else
        xParams.pucClientCertificate = NULL;

    vAlternateKeyProvisioning(&xParams);
}
#endif

#include "mbedtls/base64.h"

int aknano_verify_data(const unsigned char *data, size_t data_len, const unsigned char *signature, size_t signature_len)
{
    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle = 0;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t *pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;
    // unsigned char data_sha512[64];
    // mbedtls_sha512_ret(data, data_len, data_sha512, 0);

    unsigned char data_sha256[32];
    mbedtls_sha256_ret(data, data_len, data_sha256, 0);

    // const char* data =  "Heeyyyy!";

    xResult = C_GetFunctionList(&xFunctionList);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_Initialize(NULL);

    if ((CKR_OK == xResult) || (CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult))
        xResult = xFunctionList->C_GetSlotList(CK_TRUE, &xSlotId, &xCount);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_OpenSession(xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession);

    if (CKR_OK == xResult) {
        xSessionOpen = CK_TRUE;

        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                                //CKO_PRIVATE_KEY,
                                                CKO_PUBLIC_KEY,
                                                &xHandle );
    }
    LogInfo((ANSI_COLOR_YELLOW "*** aknano_verify_data 3 *** data_len=%d xFindObjectWithLabelAndClass xResult=%d" ANSI_COLOR_RESET, data_len, xResult));

    CK_MECHANISM xMech = { 0 };
    xMech.mechanism = CKM_ECDSA;


    if( CKR_OK == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = xFunctionList->C_VerifyInit( xSession,
                                    &xMech,
                                    xHandle );
    }
        LogInfo((ANSI_COLOR_YELLOW "*** aknano_verify_data 3 *** C_VerifyInit xResult=%d" ANSI_COLOR_RESET, xResult));

    if( CKR_OK == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = xFunctionList->C_Verify( xSession,
                                    data_sha256,
                                    32,
                                    signature,
                                    signature_len );
    }
    LogInfo((ANSI_COLOR_YELLOW "*** aknano_verify_data 3 *** C_Verify xResult=%d" ANSI_COLOR_RESET, xResult));

    if (xSessionOpen == CK_TRUE)
        (void)xFunctionList->C_CloseSession(xSession);
    
    return 0;
}

int aknano_sign_data(const unsigned char *data, size_t data_len, unsigned char *signature, size_t *signature_len)
{
    // const char *enc_data = "BD9E420I6uAkVhVruhdU68uz6HsZuqIeokXIerWkGj8WcaMHYLQrI9QM9WNE4XHui/elEajD91n5PczeZhHZ32II1khWCdRrFBLm4XrzPmPVMpNjopMQ1KNUMrHgq0oIV2TyvwKI671QWma5dsTNlq2t";
    int ret;
    // char decoded_data[2048] = {0};
    int olen;
    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_sign_data *** data_len=%d *signature_len=%d", data_len, *signature_len));

    // ret = mbedtls_base64_decode(decoded_data, sizeof(decoded_data), &olen, enc_data, sizeof(enc_data));
    // if (ret) {
    //     LogError(("aknano_sign_data: Invalid base64 string"));;
    //     return -1;
    // }

    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_sign_data 2 ***"));

    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle = 0;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t *pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;

    // unsigned char data_sha512[64];
    // mbedtls_sha512_ret(data, data_len, data_sha512, 0);
    unsigned char data_sha256[32];
    mbedtls_sha256_ret(data, data_len, data_sha256, 0);
    // const char* data =  "Heeyyyy!";

    xResult = C_GetFunctionList(&xFunctionList);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_Initialize(NULL);

    if ((CKR_OK == xResult) || (CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult))
        xResult = xFunctionList->C_GetSlotList(CK_TRUE, &xSlotId, &xCount);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_OpenSession(xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession);

    if (CKR_OK == xResult) {
        xSessionOpen = CK_TRUE;

        xResult = xFindObjectWithLabelAndClass( xSession,
                                                pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                                CKO_PRIVATE_KEY,
                                                &xHandle );
    }

    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_sign_data 3 *** xFindObjectWithLabelAndClass xResult=%d", xResult));


    CK_MECHANISM xMech = { 0 };
    xMech.mechanism = CKM_ECDSA;


    if( CKR_OK == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = xFunctionList->C_SignInit( xSession,
                                    &xMech,
                                    xHandle );
    }
    

    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_sign_data *** C_SignInit xResult=%d", xResult));
    if( CKR_OK == xResult )
    {
        xResult = xFunctionList->C_Sign( ( CK_SESSION_HANDLE ) xSession,
                                                           data_sha256,
                                                           32,
                                                           signature,
                                                           ( CK_ULONG_PTR ) signature_len );
    }


    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_sign_data *** C_Sign xResult=%d *signature_len=%d", xResult, *signature_len));


    // int error;
    // int decrypttext_len;
    // char decrypttext[2048];
    // /* Initialize the decryption operation in the session */

    // CK_MECHANISM mechanism;
    // mechanism.mechanism = 0;
    // mechanism.pParameter = NULL;
    // mechanism.ulParameterLen = 0;

	// xResult = C_DecryptInit(xSession, &mechanism, xHandle);
	// if (xResult != CKR_OK) {
    //     LogError(("C_DecryptInit: rv = 0x%.8X\n", xResult));
    // }

	// /* Decrypt the entire ciphertext string */
	// decrypttext_len = sizeof (decrypttext);
	// xResult = C_Decrypt(xSession, (CK_BYTE_PTR)decoded_data, strnlen(decoded_data, sizeof(decoded_data)),
	//     decrypttext, &decrypttext_len);

	// if (xResult != CKR_OK) {
	// 	LogError(("C_Decrypt: rv = 0x%.8X\n", xResult));
	// 	error = 1;
	// 	return -1;
	// }

	// LogInfo(("\n\n%d bytes decrypted!!!\n\n", decrypttext_len));

	// /* Print the decryption results */
	// LogInfo(("The value of the decryption is:\n%s", decrypttext));

	LogInfo(("\n aknano_sign_data Done!!!\n"));

    if (xSessionOpen == CK_TRUE)
        (void)xFunctionList->C_CloseSession(xSession);

    
    return xResult;



}

#if 0
int aknano_decrypt_data()
{
    const char *enc_data = "BD9E420I6uAkVhVruhdU68uz6HsZuqIeokXIerWkGj8WcaMHYLQrI9QM9WNE4XHui/elEajD91n5PczeZhHZ32II1khWCdRrFBLm4XrzPmPVMpNjopMQ1KNUMrHgq0oIV2TyvwKI671QWma5dsTNlq2t";
    int ret;
    char decoded_data[2048] = {0};
    int olen;
    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_decrypt_data ***"));

    ret = mbedtls_base64_decode(decoded_data, sizeof(decoded_data), &olen, enc_data, sizeof(enc_data));
    if (ret) {
        LogError(("aknano_decrypt_data: Invalid base64 string"));;
        return -1;
    }

    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_decrypt_data 2 ***"));

    /* Find the certificate */
    CK_OBJECT_HANDLE xHandle = 0;
    CK_RV xResult;
    CK_FUNCTION_LIST_PTR xFunctionList;
    CK_SLOT_ID xSlotId;
    CK_ULONG xCount = 1;
    CK_SESSION_HANDLE xSession;
    CK_ATTRIBUTE xTemplate = { 0 };
    uint8_t *pucCert = NULL;
    CK_BBOOL xSessionOpen = CK_FALSE;

    xResult = C_GetFunctionList(&xFunctionList);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_Initialize(NULL);

    if ((CKR_OK == xResult) || (CKR_CRYPTOKI_ALREADY_INITIALIZED == xResult))
        xResult = xFunctionList->C_GetSlotList(CK_TRUE, &xSlotId, &xCount);

    if (CKR_OK == xResult)
        xResult = xFunctionList->C_OpenSession(xSlotId, CKF_SERIAL_SESSION, NULL, NULL, &xSession);

    if (CKR_OK == xResult) {
        xSessionOpen = CK_TRUE;

        // does this work for keys as well?
        xResult = prvGetCertificateHandle(xFunctionList, xSession, pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS, &xHandle);
    }
    LogInfo((ANSI_COLOR_MAGENTA "*** aknano_decrypt_data 3 ***"));

    int error;
    int decrypttext_len;
    char decrypttext[2048];
    /* Initialize the decryption operation in the session */

    CK_MECHANISM mechanism;
    mechanism.mechanism = 0;
    mechanism.pParameter = NULL;
    mechanism.ulParameterLen = 0;

	xResult = C_DecryptInit(xSession, &mechanism, xHandle);
	if (xResult != CKR_OK) {
        LogError(("C_DecryptInit: rv = 0x%.8X\n", xResult));
    }

	/* Decrypt the entire ciphertext string */
	decrypttext_len = sizeof (decrypttext);
	xResult = C_Decrypt(xSession, (CK_BYTE_PTR)decoded_data, strnlen(decoded_data, sizeof(decoded_data)),
	    decrypttext, &decrypttext_len);

	if (xResult != CKR_OK) {
		LogError(("C_Decrypt: rv = 0x%.8X\n", xResult));
		error = 1;
		return -1;
	}

	LogInfo(("\n\n%d bytes decrypted!!!\n\n", decrypttext_len));

	/* Print the decryption results */
	LogInfo(("The value of the decryption is:\n%s", decrypttext));

	LogInfo(("\nDone!!!\n"));


    if (xSessionOpen == CK_TRUE)
        (void)xFunctionList->C_CloseSession(xSession);

    return xResult;



}
#endif