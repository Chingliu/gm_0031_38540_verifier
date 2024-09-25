#include "38540.h"
#include "sm2sign.h"

ASN1_SEQUENCE(SESv1_ExtensionData) {
  ASN1_SIMPLE(SESv1_ExtensionData, extnID, ASN1_OBJECT),
  ASN1_SIMPLE(SESv1_ExtensionData, critical, ASN1_BOOLEAN),
    ASN1_SIMPLE(SESv1_ExtensionData, extnValue, ASN1_OCTET_STRING)
} static_ASN1_NDEF_SEQUENCE_END(SESv1_ExtensionData)
IMPLEMENT_ASN1_FUNCTIONS(SESv1_ExtensionData)

ASN1_SEQUENCE(CertDigestObj)  {
    ASN1_SIMPLE(CertDigestObj, type, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(CertDigestObj, value, ASN1_OCTET_STRING)
} static_ASN1_NDEF_SEQUENCE_END(CertDigestObj)
IMPLEMENT_ASN1_FUNCTIONS(CertDigestObj)

ASN1_SEQUENCE(SES_Header)  {
    ASN1_SIMPLE(SES_Header, id, ASN1_IA5STRING),
      ASN1_SIMPLE(SES_Header, version, ASN1_INTEGER),
    ASN1_SIMPLE(SES_Header, vid, ASN1_IA5STRING)
} static_ASN1_NDEF_SEQUENCE_END(SES_Header)
IMPLEMENT_ASN1_FUNCTIONS(SES_Header)

ASN1_SEQUENCE(SES_ESPictureInfo)  {
    ASN1_SIMPLE(SES_ESPictureInfo, type, ASN1_IA5STRING),
    ASN1_SIMPLE(SES_ESPictureInfo, data, ASN1_OCTET_STRING),
      ASN1_SIMPLE(SES_ESPictureInfo, width, ASN1_INTEGER),
      ASN1_SIMPLE(SES_ESPictureInfo, height, ASN1_INTEGER)
} static_ASN1_NDEF_SEQUENCE_END(SES_ESPictureInfo)
IMPLEMENT_ASN1_FUNCTIONS(SES_ESPictureInfo)

ASN1_SEQUENCE(SESv2_ESPropertyInfo)  {
      ASN1_SIMPLE(SESv2_ESPropertyInfo, type, ASN1_INTEGER),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, name, ASN1_UTF8STRING),
    ASN1_SEQUENCE_OF(SESv2_ESPropertyInfo, certs, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, createDate, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validStart, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validEnd, ASN1_UTCTIME)
} static_ASN1_NDEF_SEQUENCE_END(SESv2_ESPropertyInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_ESPropertyInfo)

ASN1_SEQUENCE(SESv4_ESPropertyInfo)  {
    ASN1_SIMPLE(SESv4_ESPropertyInfo, type, ASN1_INTEGER),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, name, ASN1_UTF8STRING),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, certListType, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(SESv4_ESPropertyInfo, certs, ASN1_OCTET_STRING),
    ASN1_SEQUENCE_OF_OPT(SESv4_ESPropertyInfo, certDigestList, CertDigestObj),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, createDate, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, validStart, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(SESv4_ESPropertyInfo, validEnd, ASN1_GENERALIZEDTIME)
} static_ASN1_NDEF_SEQUENCE_END(SESv4_ESPropertyInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_ESPropertyInfo)

ASN1_SEQUENCE(SESv2_SealInfo)  {
    ASN1_SIMPLE(SESv2_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv2_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv2_SealInfo, property, SESv2_ESPropertyInfo),
    ASN1_SIMPLE(SESv2_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv2_SealInfo, extDatas, SESv1_ExtensionData)
} static_ASN1_NDEF_SEQUENCE_END(SESv2_SealInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_SealInfo)

ASN1_SEQUENCE(SESv4_SealInfo)  {
    ASN1_SIMPLE(SESv4_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv4_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv4_SealInfo, property, SESv4_ESPropertyInfo),
    ASN1_SIMPLE(SESv4_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv4_SealInfo, extDatas, SESv1_ExtensionData)
} static_ASN1_NDEF_SEQUENCE_END(SESv4_SealInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_SealInfo)

ASN1_SEQUENCE(SESv2_SignInfo)  {
    ASN1_SIMPLE(SESv2_SignInfo, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv2_SignInfo, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv2_SignInfo, signedvalue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv2_SignInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_SignInfo)

ASN1_SEQUENCE(SESv2_Seal)  {
    ASN1_SIMPLE(SESv2_Seal, sealinfo, SESv2_SealInfo),
    ASN1_SIMPLE(SESv2_Seal, signinfo, SESv2_SignInfo)
} ASN1_SEQUENCE_END(SESv2_Seal)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_Seal)

ASN1_SEQUENCE(SESv4_Seal)  {
    ASN1_SIMPLE(SESv4_Seal, sealinfo, SESv4_SealInfo),
    ASN1_SIMPLE(SESv4_Seal, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv4_Seal, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv4_Seal, signedvalue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv4_Seal)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_Seal)

ASN1_SEQUENCE(TBSv2_Sign)  {
    ASN1_SIMPLE(TBSv2_Sign, version, ASN1_INTEGER),
    ASN1_SIMPLE(TBSv2_Sign, eseal, SESv2_Seal),
    ASN1_SIMPLE(TBSv2_Sign, timeinfo, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv2_Sign, datahash, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv2_Sign, propertyinfo, ASN1_IA5STRING),
    ASN1_SIMPLE(TBSv2_Sign, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(TBSv2_Sign, signalgid, ASN1_OBJECT)
} static_ASN1_NDEF_SEQUENCE_END(TBSv2_Sign)
IMPLEMENT_ASN1_FUNCTIONS(TBSv2_Sign)

ASN1_SEQUENCE(TBSv4_Sign)  {
    ASN1_SIMPLE(TBSv4_Sign, version, ASN1_INTEGER),
    ASN1_SIMPLE(TBSv4_Sign, eseal, SESv4_Seal),
    ASN1_SIMPLE(TBSv4_Sign, timeinfo, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(TBSv4_Sign, datahash, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv4_Sign, propertyinfo, ASN1_IA5STRING),
    ASN1_SEQUENCE_OF_OPT(TBSv4_Sign, extDatas, X509_EXTENSION)
} static_ASN1_NDEF_SEQUENCE_END(TBSv4_Sign)
IMPLEMENT_ASN1_FUNCTIONS(TBSv4_Sign)

ASN1_SEQUENCE(SESv2_Signature)  {
    ASN1_SIMPLE(SESv2_Signature, tosign, TBSv2_Sign),
    ASN1_SIMPLE(SESv2_Signature, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv2_Signature)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_Signature)

ASN1_SEQUENCE(SESv4_Signature)  {
    ASN1_SIMPLE(SESv4_Signature, tosign, TBSv4_Sign),
    ASN1_SIMPLE(SESv4_Signature, cert, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv4_Signature, signalgid, ASN1_OBJECT),
    ASN1_SIMPLE(SESv4_Signature, signedvalue, ASN1_BIT_STRING),
    ASN1_OPT(SESv4_Signature, timestamp, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(SESv4_Signature)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_Signature)

namespace gm {

      void v4deleter(SESv4_Signature* ptr) {
        if (ptr)SESv4_Signature_free(ptr);
      }
      void v2deleter(SESv2_Signature* ptr) {
        if (ptr)SESv2_Signature_free(ptr);
      }

      void x509free(X509* cert) {
        if (cert)
        {
          X509_free(cert);
        }
      }
      void Openssl_deleter(unsigned char *ptr) {
        if (ptr)
        {
          OPENSSL_free(ptr);
        }
      }
      C38540::C38540(const unsigned char *data, long len):m_psign(d2i_SESv4_Signature(NULL, &data, len), &v4deleter),
      m_signer_cert(nullptr, &x509free){

      }
      C38540::~C38540() {

      }

      int C38540::sign_verify(void *sign_handler, unsigned char * digest, long digest_len) {
        if (!m_psign)
        {
          return m_error = ErrDataFormat;
        }
        if (!digest || digest_len <= 0)
        {
          return m_error = ErrInvalidDigest;
        }
        m_error = verify_signature_signed_value();
        if (m_error)
          return m_error;
        return 0;
      }
      int C38540::verify_signature_signed_value() {
        //验证电子签章签名值是否正确
        //解析所得的签章信息、签章者证书和签名算法标识,验证电子签章签名值。

        if (!m_psign->cert)
        {
          return m_error = ErrInvalidSignerCert;
        }
        if (!m_psign->tosign)
        {
          return m_error = ErrInvalidTBSign;
        }
        if (!m_psign->signedvalue)
        {
          return m_error = ErrInvalidSignValue;
        }
        std::string signalgid("1.2.156.10197.1.501");
        if (m_psign->signalgid) {
          auto objtxt_len = OBJ_obj2txt(nullptr, 0, m_psign->signalgid, 1);
          if (objtxt_len <=0)
          {
            return m_error = ErrBadsignalgid;
          }
          signalgid.resize(objtxt_len + 1);
          OBJ_obj2txt(&signalgid[0], objtxt_len+1, m_psign->signalgid, 1);
        }
        if ( 0 == signalgid.compare("1.2.156.10197.1.501") )
        {
          return m_error = ErrNotSupoortSignalgId;
        }
        auto octet_data = ASN1_STRING_get0_data(m_psign->cert);
        int octet_len = ASN1_STRING_length(m_psign->cert);
        m_signer_cert.reset(d2i_X509(NULL, &octet_data, octet_len));
        if (!m_signer_cert)
        {
          return m_error = ErrInvalidSignerCert;
        }
        unsigned char *tbsign_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_tbsign_der(nullptr, &Openssl_deleter);
        int tbsign_len = i2d_TBSv4_Sign(m_psign->tosign, &tbsign_der);
        guard_tbsign_der.reset(tbsign_der);
        if (tbsign_len < 0) {
          return m_error = ErrInvalidTBSign;
        }
        auto signed_value = ASN1_STRING_get0_data(m_psign->signedvalue);
        auto signed_value_len = ASN1_STRING_length(m_psign->signedvalue);

        EVP_CUNSTOM evp;
        evp.pkey = X509_get_pubkey(m_signer_cert.get());
        unsigned char *pkey_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_pkey_der(nullptr, &Openssl_deleter);
        int der_len = i2d_PUBKEY(evp.pkey, &pkey_der);
        guard_pkey_der.reset(pkey_der);
        if (der_len<= 0)
        {
          return m_error = ErrNoPubKey;
        }
        sm2PublicKey sm2verify(pkey_der, der_len);
        std::string errmsg;
        if (!sm2verify.SignatureVerification(signed_value, signed_value_len, tbsign_der, tbsign_len, errmsg)) {
          return m_error = ErrSignatureSignedValuCheckFailed;
        }

        return 0;
      }
      int C38540::sign_get_cert() {
        return 0;
      }
      int C38540::sign_get_picture() {
        return 0;
      }
      int C38540::sign_get_seal_name() {
        return 0;
      }



      C0031::C0031(const unsigned char *data, long len) :m_psign(d2i_SESv2_Signature(NULL, &data, len), &v2deleter) {

      }
      C0031::~C0031() {

      }

      int C0031::sign_verify(void *sign_handler, unsigned char * digest, long digest_len) {
        return 0;
      }
      int C0031::sign_get_cert() {
        return 0;
      }
      int C0031::sign_get_picture() {
        return 0;
      }
      int C0031::sign_get_seal_name() {
        return 0;
      }
}