#include "38540.h"
#include "sm2sign.h"
#include <openssl/x509v3.h>
ASN1_SEQUENCE(SESv1_ExtensionData) {
  ASN1_SIMPLE(SESv1_ExtensionData, extnID, ASN1_OBJECT),
  ASN1_SIMPLE(SESv1_ExtensionData, critical, ASN1_BOOLEAN),
    ASN1_SIMPLE(SESv1_ExtensionData, extnValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SESv1_ExtensionData)
IMPLEMENT_ASN1_FUNCTIONS(SESv1_ExtensionData)

ASN1_SEQUENCE(CertDigestObj)  {
    ASN1_SIMPLE(CertDigestObj, type, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(CertDigestObj, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CertDigestObj)
IMPLEMENT_ASN1_FUNCTIONS(CertDigestObj)

ASN1_SEQUENCE(SES_Header)  {
    ASN1_SIMPLE(SES_Header, id, ASN1_IA5STRING),
      ASN1_SIMPLE(SES_Header, version, ASN1_INTEGER),
    ASN1_SIMPLE(SES_Header, vid, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(SES_Header)
IMPLEMENT_ASN1_FUNCTIONS(SES_Header)

ASN1_SEQUENCE(SES_ESPictureInfo)  {
    ASN1_SIMPLE(SES_ESPictureInfo, type, ASN1_IA5STRING),
    ASN1_SIMPLE(SES_ESPictureInfo, data, ASN1_OCTET_STRING),
      ASN1_SIMPLE(SES_ESPictureInfo, width, ASN1_INTEGER),
      ASN1_SIMPLE(SES_ESPictureInfo, height, ASN1_INTEGER)
} ASN1_SEQUENCE_END(SES_ESPictureInfo)
IMPLEMENT_ASN1_FUNCTIONS(SES_ESPictureInfo)

ASN1_SEQUENCE(SESv2_ESPropertyInfo)  {
      ASN1_SIMPLE(SESv2_ESPropertyInfo, type, ASN1_INTEGER),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, name, ASN1_UTF8STRING),
    ASN1_SEQUENCE_OF(SESv2_ESPropertyInfo, certs, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, createDate, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validStart, ASN1_UTCTIME),
    ASN1_SIMPLE(SESv2_ESPropertyInfo, validEnd, ASN1_UTCTIME)
} ASN1_SEQUENCE_END(SESv2_ESPropertyInfo)
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
} ASN1_SEQUENCE_END(SESv4_ESPropertyInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv4_ESPropertyInfo)

ASN1_SEQUENCE(SESv2_SealInfo)  {
    ASN1_SIMPLE(SESv2_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv2_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv2_SealInfo, property, SESv2_ESPropertyInfo),
    ASN1_SIMPLE(SESv2_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv2_SealInfo, extDatas, SESv1_ExtensionData)
} ASN1_SEQUENCE_END(SESv2_SealInfo)
IMPLEMENT_ASN1_FUNCTIONS(SESv2_SealInfo)

ASN1_SEQUENCE(SESv4_SealInfo)  {
    ASN1_SIMPLE(SESv4_SealInfo, header, SES_Header),
    ASN1_SIMPLE(SESv4_SealInfo, esid, ASN1_IA5STRING),
    ASN1_SIMPLE(SESv4_SealInfo, property, SESv4_ESPropertyInfo),
    ASN1_SIMPLE(SESv4_SealInfo, picture, SES_ESPictureInfo),
    ASN1_SEQUENCE_OF_OPT(SESv4_SealInfo, extDatas, SESv1_ExtensionData)
} ASN1_SEQUENCE_END(SESv4_SealInfo)
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
} ASN1_SEQUENCE_END(TBSv2_Sign)
IMPLEMENT_ASN1_FUNCTIONS(TBSv2_Sign)

ASN1_SEQUENCE(TBSv4_Sign)  {
    ASN1_SIMPLE(TBSv4_Sign, version, ASN1_INTEGER),
    ASN1_SIMPLE(TBSv4_Sign, eseal, SESv4_Seal),
    ASN1_SIMPLE(TBSv4_Sign, timeinfo, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(TBSv4_Sign, datahash, ASN1_BIT_STRING),
    ASN1_SIMPLE(TBSv4_Sign, propertyinfo, ASN1_IA5STRING),
    ASN1_SEQUENCE_OF_OPT(TBSv4_Sign, extDatas, X509_EXTENSION)
} ASN1_SEQUENCE_END(TBSv4_Sign)
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
      m_signer_cert(nullptr, &x509free),
      m_seal_maker_cert(nullptr, &x509free) {

      }
      C38540::~C38540() {

      }

      int C38540::sign_verify(unsigned char * digest, long digest_len) {
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
        m_error = verify_signer_cert_inside_seal();
        if (m_error)
          return m_error;
        m_error = verify_seal();
        if (m_error)
          return m_error;
        m_error = verify_signer_cert_valid();
        if (m_error)
          return m_error;
        m_error = verify_doc_hash(digest, digest_len);
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
      int C38540::verify_signer_cert_inside_seal() {
        //验证签章者证书与电子印章的匹配性
        if (!m_psign->tosign->eseal)
        {
          return m_error = ErrTBSNoSeal;
        }
        auto eseal = m_psign->tosign->eseal;
        if (!eseal->sealinfo)
        {
          return m_error = ErrSealNoSealInfo;
        }
        if (!eseal->sealinfo->property) {
          return m_error = ErrSealNoProperty;
        }
        auto property = eseal->sealinfo->property;
        if (!property->certListType)
        {
          return m_error = ErrSealNoCertListType;
        }
        auto cert_list_type =  ASN1_INTEGER_get(property->certListType);
        if (cert_list_type == 2)
        {
          //TODO
        }
        else {
          if (m_error = compare_signer_cert(property->certs, m_psign->cert)!= 0)
          {
            return m_error;
          }
        }
        return 0;
      }
      int CGMVerifier_if::compare_signer_cert(STACK_OF(ASN1_OCTET_STRING) *certs, ASN1_OCTET_STRING *cert) {
        //auto cert = ASN1_STRING_get0_data(m_psign->cert);
        //int certlen = ASN1_STRING_length(m_psign->cert);
        int num_certs = sk_ASN1_OCTET_STRING_num(certs);
        if (num_certs <=0)
        {
          return ErrSignerCertCompareFailed;
        }
 
        for (int i = 0; i < num_certs; i++) {
          // 获取第 i 个 ASN1_OCTET_STRING 对象
          ASN1_OCTET_STRING *octet_string = sk_ASN1_OCTET_STRING_value(certs, i);
          if (octet_string != NULL) {
            // 获取 ASN1_OCTET_STRING 的数据和长度
            //const unsigned char *data = ASN1_STRING_get0_data(octet_string);
            //int length = ASN1_STRING_length(octet_string);
            if (0 == ASN1_OCTET_STRING_cmp(cert, octet_string))
              return 0;
          }
        }
        return ErrSignerCertCompareFailed;
      }
      int C38540::verify_seal() {
        //验证电子签章有效性
        if (!m_psign->tosign->eseal)
        {
          return m_error = ErrTBSNoSeal;
        }
        auto seal = m_psign->tosign->eseal;
        m_error = check_seal_signvalue(seal);
        if (m_error != 0)
        {
          return m_error;
        }
        m_error = check_seal_maker_cert();
        if (m_error != 0)
        {
          return m_error;
        }
        m_error = check_seal_time(seal);
        if (m_error != 0)
        {
          return m_error;
        }
        return m_error;
      }
      int C38540::check_seal_signvalue(SESv4_Seal *eseal) {
        //验证电子印章签名值是否正确
        if (!eseal->cert)
        {
          return m_error = ErrInvalidSealCert;
        }
        if (!eseal->sealinfo)
        {
          return m_error = ErrSealNoSealInfo;
        }
        if (!eseal->signalgid)
        {
          return m_error = ErrInvalidSealSignalgId;
        }
        if (!eseal->signedvalue)
        {
          return m_error = ErrSealSignValue;
        }
        std::string signalgid("1.2.156.10197.1.501");
        if (eseal->signalgid) {
          auto objtxt_len = OBJ_obj2txt(nullptr, 0, eseal->signalgid, 1);
          if (objtxt_len <= 0)
          {
            return m_error = ErrBadsignalgid;
          }
          signalgid.resize(objtxt_len + 1);
          OBJ_obj2txt(&signalgid[0], objtxt_len + 1, eseal->signalgid, 1);
        }
        if (0 == signalgid.compare("1.2.156.10197.1.501"))
        {
          return m_error = ErrNotSupoortSignalgId;
        }
        auto octet_data = ASN1_STRING_get0_data(eseal->cert);
        int octet_len = ASN1_STRING_length(eseal->cert);
        m_seal_maker_cert.reset(d2i_X509(NULL, &octet_data, octet_len));
        if (!m_seal_maker_cert)
        {
          return m_error = ErrInvalidSealMakerCert;
        }
        unsigned char *tbsign_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_tbsign_der(nullptr, &Openssl_deleter);
        int tbsign_len = i2d_SESv4_SealInfo(eseal->sealinfo, &tbsign_der);
        guard_tbsign_der.reset(tbsign_der);
        if (tbsign_len < 0) {
          return m_error = ErrInvalidTBSign;
        }
        auto signed_value = ASN1_STRING_get0_data(eseal->signedvalue);
        auto signed_value_len = ASN1_STRING_length(eseal->signedvalue);

        EVP_CUNSTOM evp;
        evp.pkey = X509_get_pubkey(m_seal_maker_cert.get());
        unsigned char *pkey_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_pkey_der(nullptr, &Openssl_deleter);
        int der_len = i2d_PUBKEY(evp.pkey, &pkey_der);
        guard_pkey_der.reset(pkey_der);
        if (der_len <= 0)
        {
          return m_error = ErrNoPubKey;
        }
        sm2PublicKey sm2verify(pkey_der, der_len);
        std::string errmsg;
        if (!sm2verify.SignatureVerification(signed_value, signed_value_len, tbsign_der, tbsign_len, errmsg)) {
          return m_error = ErrSealSignedValuCheckFailed;
        }
        return 0;
      }
      int CGMVerifier_if::check_cert(X509 *cert) {
        time_t current_time = time(NULL);

        // 获取证书有效期
        ASN1_TIME *not_before = X509_get_notBefore(cert);
        ASN1_TIME *not_after = X509_get_notAfter(cert);

        if (X509_cmp_time(not_before, &current_time) > 0) {
          return m_error = ErrSealMakerCertNotInEffect;
        }
        else if (X509_cmp_time(not_after, &current_time) < 0) {
          return m_error = ErrSealMakerCertExpired;
        }


        // 获取 Key Usage 扩展字段
        ASN1_BIT_STRING *usage = (ASN1_BIT_STRING *)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
        if (usage) {
          int usage_flags = usage->data[0]; // Key Usage 是一个 bit string，通常存储在第一个字节
          if (usage_flags & KU_DIGITAL_SIGNATURE) {
            printf("Key Usage includes Digital Signature\n");
          }
          if (usage_flags & KU_KEY_ENCIPHERMENT) {
            printf("Key Usage includes Key Encipherment\n");
          }
          // 其他可能的 Key Usage 校验
        }
        else {
          printf("No Key Usage found.\n");
        }

        // 获取 Extended Key Usage 扩展字段
        STACK_OF(ASN1_OBJECT) *eku = (STACK_OF(ASN1_OBJECT) *) X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
        if (eku) {
          int num_eku = sk_ASN1_OBJECT_num(eku);
          for (int i = 0; i < num_eku; i++) {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
            char buf[80];
            OBJ_obj2txt(buf, sizeof(buf), obj, 1);
            printf("Extended Key Usage: %s\n", buf);
          }
        }
        else {
          printf("No Extended Key Usage found.\n");
        }

        return 0;
      }
      int C38540::check_seal_maker_cert() {
        if (!m_seal_maker_cert)
        {
          return m_error = ErrInvalidSealMakerCert;
        }
        //验证制章者证书的有效性，验证项至少包括：制章者证书信任链验证、制章者证书有效期验证、制章者证书是否被撤销、密钥用法是否正确
        //TODO 制章者证书信任链验证,制章者证书是否被撤销, 需要增加在线验证模式
        //TODO 
        return check_cert(m_seal_maker_cert.get());
      }
      int C38540::verify_signer_cert_valid() {
        if (!m_signer_cert)
        {
          return m_error = ErrInvalidSealMakerCert;
        }
        //验证签章者证书的有效性，验证项至少包括：签章者证书信任链验证、签章者证书有效期验证、签章者证书是否被撤销、密钥用法是否正确
        //TODO 签章者证书信任链验证,签章者证书是否被撤销, 需要增加在线验证模式
        //TODO 
        auto iret = check_cert(m_signer_cert.get());
        if (iret != 0 && iret != ErrSealMakerCertExpired)
        {
          return m_error = iret;
        }
        auto timeinfo = m_psign->tosign->timeinfo;
        // 获取证书有效期
        ASN1_TIME *not_before = X509_get_notBefore(m_signer_cert.get());
        ASN1_TIME *not_after = X509_get_notAfter(m_signer_cert.get());
        tm sign_tm;
        //TODO有问题
        ASN1_TIME_to_tm(timeinfo, &sign_tm);
        auto sign_timet = mktime(&sign_tm);
        if (X509_cmp_time(not_before, &sign_timet) > 0) {
          return m_error = ErrSealMakerCertNotInEffect;
        }
        else if (X509_cmp_time(not_after, &sign_timet) < 0) {
          return m_error = ErrSealMakerCertExpired;
        }
        return 0;
      }
      int C38540::check_seal_time(SESv4_Seal *eseal) {
        if (!eseal->sealinfo)
        {
          return m_error = ErrSealNoSealInfo;
        }
        if (!eseal->sealinfo->property) {
          return m_error = ErrSealNoProperty;
        }
        auto property = eseal->sealinfo->property;
        if (!property->validStart || !property->validEnd)
        {
          return m_error = ErrSealNoValidTime;
        }
        m_error = 0;
        time_t current_time = time(NULL);
        m_error = check_time(property->validStart, property->validEnd, current_time);
        return m_error;
      }
      int C38540::check_time(ASN1_GENERALIZEDTIME *validStart, ASN1_GENERALIZEDTIME *validEnd, time_t timepoint) {
        int iret = 0;
        ASN1_GENERALIZEDTIME *current_asn1_time = ASN1_GENERALIZEDTIME_new();
        do
        {
          ASN1_TIME_set(current_asn1_time, timepoint);

          // 比较当前时间和 validStart
          if (ASN1_TIME_compare(current_asn1_time, validStart) < 0) {
            iret = ErrValidTimeStart;
            break;
          }

          // 比较当前时间和 validEnd
          if (ASN1_TIME_compare(current_asn1_time, validEnd) > 0) {
            iret = ErrValidTimeEnd;
            break;
          }
        } while (0);
        ASN1_GENERALIZEDTIME_free(current_asn1_time);
        return iret;
      }
      int C38540::verify_doc_hash(unsigned char * digest, long digest_len) {
        //TODO: 
        auto datahash = ASN1_STRING_get0_data(m_psign->tosign->datahash);
        auto datahash_len = ASN1_STRING_length(m_psign->tosign->datahash);
        if (datahash_len != digest_len)
        {
          return ErrDocHashCheck;
        }
        if (0 == memcpy(digest, datahash, digest_len))
        {
          return 0;
        }
        return ErrDocHashCheck;
      }
      void * C38540::sign_get_cert(unsigned int type) {
        switch (type)
        {
        case 1:
          return m_signer_cert.get();
        case 2:
          return m_seal_maker_cert.get();
        default:
          break;
        }
        return nullptr;
      }
      int C38540::sign_get_picture() {
        return 0;
      }
      int C38540::sign_get_seal_name() {
        return 0;
      }



      C0031::C0031(const unsigned char *data, long len) :m_psign(d2i_SESv2_Signature(NULL, &data, len), &v2deleter),
        m_signer_cert(nullptr, &x509free),
        m_seal_maker_cert(nullptr, &x509free) {

      }
      C0031::~C0031() {

      }

      int C0031::sign_verify(unsigned char * digest, long digest_len) {
        m_error = verify_signature_signed_value();
        if (m_error)
        {
          return m_error;
        }
        m_error = verify_signer_cert_inside_seal();
        if (m_error)
        {
          return m_error;
        }
        m_error = verify_signer_cert_valid();
        if (m_error)
        {
          return m_error;
        }
        m_error = verify_seal();
        if (m_error)
        {
          return m_error;
        }
        m_error = verify_doc_hash(digest, digest_len);
        if (m_error)
        {
          return m_error;
        }
        return 0;
      }
      void * C0031::sign_get_cert(unsigned int type) {
        return 0;
      }
      int C0031::sign_get_picture() {
        return 0;
      }
      int C0031::sign_get_seal_name() {
        return 0;
      }
      int C0031::verify_signature_signed_value() {
        if (!m_psign)
        {
          return m_error = ErrDataFormat;
        }
        if (!m_psign->signature)
        {
          return m_error = ErrInvalidSignValue;
        }
        if (!m_psign->tosign)
        {
          return m_error = ErrInvalidTBSign;
        }
        if (!m_psign->tosign->cert)
        {
          return m_error = ErrInvalidSignerCert;
        }
        auto tbs = m_psign->tosign;
        if (!tbs->datahash)
        {
          return m_error = ErrInvalidDigest;
        }
        if (!tbs->eseal)
        {
          return m_error = ErrTBSNoSeal;
        }
        if (!tbs->signalgid)
        {
          return m_error = ErrBadsignalgid;
        }
        if (!tbs->timeinfo)
        {
          return m_error = ErrNoTimeInfo;
        }
        std::string signalgid("1.2.156.10197.1.501");
        if (tbs->signalgid) {
          auto objtxt_len = OBJ_obj2txt(nullptr, 0, tbs->signalgid, 1);
          if (objtxt_len <= 0)
          {
            return m_error = ErrBadsignalgid;
          }
          signalgid.resize(objtxt_len + 1);
          OBJ_obj2txt(&signalgid[0], objtxt_len + 1, tbs->signalgid, 1);
        }
        if (0 == signalgid.compare("1.2.156.10197.1.501"))
        {
          return m_error = ErrNotSupoortSignalgId;
        }
        //TODO RSA
        auto octet_data = ASN1_STRING_get0_data(tbs->cert);
        int octet_len = ASN1_STRING_length(tbs->cert);
        m_signer_cert.reset(d2i_X509(NULL, &octet_data, octet_len));
        if (!m_signer_cert)
        {
          return m_error = ErrInvalidSignerCert;
        }
        unsigned char *tbsign_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_tbsign_der(nullptr, &Openssl_deleter);
        int tbsign_len = i2d_TBSv2_Sign(m_psign->tosign, &tbsign_der);
        guard_tbsign_der.reset(tbsign_der);
        if (tbsign_len < 0) {
          return m_error = ErrInvalidTBSign;
        }
        auto signed_value = ASN1_STRING_get0_data(m_psign->signature);
        auto signed_value_len = ASN1_STRING_length(m_psign->signature);

        EVP_CUNSTOM evp;
        evp.pkey = X509_get_pubkey(m_signer_cert.get());
        unsigned char *pkey_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_pkey_der(nullptr, &Openssl_deleter);
        int der_len = i2d_PUBKEY(evp.pkey, &pkey_der);
        guard_pkey_der.reset(pkey_der);
        if (der_len <= 0)
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

      int C0031::verify_doc_hash(unsigned char * digest, long digest_len) {
        //TODO: 
        auto datahash = ASN1_STRING_get0_data(m_psign->tosign->datahash);
        auto datahash_len = ASN1_STRING_length(m_psign->tosign->datahash);
        if (datahash_len != digest_len)
        {
          return ErrDocHashCheck;
        }
        if (0 == memcpy(digest, datahash, digest_len))
        {
          return 0;
        }
        return ErrDocHashCheck;
      }
      int C0031::verify_signer_cert_inside_seal() {
        //验证签章者证书与电子印章的匹配性
        if (!m_psign->tosign->eseal)
        {
          return m_error = ErrTBSNoSeal;
        }
        auto eseal = m_psign->tosign->eseal;
        if (!eseal->sealinfo)
        {
          return m_error = ErrSealNoSealInfo;
        }
        if (!eseal->sealinfo->property) {
          return m_error = ErrSealNoProperty;
        }
        auto property = eseal->sealinfo->property;
        {
          if (m_error = compare_signer_cert(property->certs, m_psign->tosign->cert) != 0)
          {
            return m_error;
          }
        }
        return 0;
      }
      int C0031::verify_signer_cert_valid() {
        if (!m_signer_cert)
        {
          return m_error = ErrInvalidSealMakerCert;
        }
        //验证签章者证书的有效性，验证项至少包括：签章者证书信任链验证、签章者证书有效期验证、签章者证书是否被撤销、密钥用法是否正确
        //TODO 签章者证书信任链验证,签章者证书是否被撤销, 需要增加在线验证模式
        //TODO 
        auto iret = check_cert(m_signer_cert.get());
        if (iret !=0 && iret != ErrSealMakerCertExpired)
        {
          return m_error = iret;
        }
        auto timeinfo = m_psign->tosign->timeinfo;
        // 获取证书有效期
        ASN1_TIME *not_before = X509_get_notBefore(m_signer_cert.get());
        ASN1_TIME *not_after = X509_get_notAfter(m_signer_cert.get());
        tm sign_tm;
        ASN1_TIME_to_tm(timeinfo, &sign_tm);
        auto sign_timet = mktime(&sign_tm);
        if (X509_cmp_time(not_before, &sign_timet) > 0) {
          return m_error = ErrSealMakerCertNotInEffect;
        }
        else if (X509_cmp_time(not_after, &sign_timet) < 0) {
          return m_error = ErrSealMakerCertExpired;
        }
        return 0;
      }

      int C0031::verify_seal() {
        //验证电子签章有效性
        if (!m_psign->tosign->eseal)
        {
          return m_error = ErrTBSNoSeal;
        }
        auto seal = m_psign->tosign->eseal;
        m_error = check_seal_signvalue(seal);
        if (m_error != 0)
        {
          return m_error;
        }
        //TODO
        //m_error = check_seal_maker_cert();
        if (m_error != 0)
        {
          return m_error;
        }
        //TODO
       // m_error = check_seal_time(seal);
        if (m_error != 0)
        {
          return m_error;
        }
        return m_error;
      }

      typedef struct SESv2_Seal_t {
        SESv2_SealInfo *sealinfo;
        ASN1_OCTET_STRING *cert;
        ASN1_OBJECT *signalgid;
      }SESv2_SealSignRange;
      DECLARE_ASN1_FUNCTIONS(SESv2_SealSignRange);

      ASN1_SEQUENCE(SESv2_SealSignRange) {
        ASN1_SIMPLE(SESv2_SealSignRange, sealinfo, SESv2_SealInfo),
          ASN1_SIMPLE(SESv2_SealSignRange, cert, ASN1_OCTET_STRING),
          ASN1_SIMPLE(SESv2_SealSignRange, signalgid, ASN1_OBJECT)
      } ASN1_SEQUENCE_END(SESv2_SealSignRange)
     IMPLEMENT_ASN1_FUNCTIONS(SESv2_SealSignRange)

      int C0031::check_seal_signvalue(SESv2_Seal *eseal) {
        //验证电子印章签名值是否正确
        auto signinfo = eseal->signinfo;
        auto sealinfo = eseal->sealinfo;
        if (!signinfo->cert)
        {
          return m_error = ErrInvalidSealCert;
        }
        if (!eseal->sealinfo)
        {
          return m_error = ErrSealNoSealInfo;
        }
        if (!signinfo->signalgid)
        {
          return m_error = ErrInvalidSealSignalgId;
        }
        if (!signinfo->signedvalue)
        {
          return m_error = ErrSealSignValue;
        }
        std::string signalgid("1.2.156.10197.1.501");
        if (signinfo->signalgid) {
          auto objtxt_len = OBJ_obj2txt(nullptr, 0, signinfo->signalgid, 1);
          if (objtxt_len <= 0)
          {
            return m_error = ErrBadsignalgid;
          }
          signalgid.resize(objtxt_len + 1);
          OBJ_obj2txt(&signalgid[0], objtxt_len + 1, signinfo->signalgid, 1);
        }
        if (0 == signalgid.compare("1.2.156.10197.1.501"))
        {
          return m_error = ErrNotSupoortSignalgId;
        }
        auto octet_data = ASN1_STRING_get0_data(signinfo->cert);
        int octet_len = ASN1_STRING_length(signinfo->cert);
        m_seal_maker_cert.reset(d2i_X509(NULL, &octet_data, octet_len));
        if (!m_seal_maker_cert)
        {
          return m_error = ErrInvalidSealMakerCert;
        }
#if 0
        unsigned char *tbsign_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_tbsign_der(nullptr, &Openssl_deleter);
        int tbsign_len = i2d_SESv2_SealInfo(eseal->sealinfo, &tbsign_der);
        guard_tbsign_der.reset(tbsign_der);
        if (tbsign_len < 0) {
          return m_error = ErrInvalidTBSign;
        }

        // 获取 signalgid 的数据和长度
        int signalgid_len = i2d_ASN1_OBJECT(signinfo->signalgid, NULL); // 获取 signalgid 编码后的长度
        unsigned char *signalgid_data = (unsigned char *)OPENSSL_malloc(signalgid_len);
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_signalgid(nullptr, &Openssl_deleter);
        guard_signalgid.reset(signalgid_data);
        unsigned char *p = signalgid_data;
        i2d_ASN1_OBJECT(signinfo->signalgid, &p); // 对象序列化为 DER 格式

        unsigned char *seal_tbs = (unsigned char *)OPENSSL_malloc(tbsign_len + octet_len + signalgid_len);
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_sealtbs(nullptr, &Openssl_deleter);
        guard_signalgid.reset(seal_tbs);
        memcpy(seal_tbs, tbsign_der, tbsign_len);
        memcpy(seal_tbs + tbsign_len, octet_data, octet_len);
        memcpy(seal_tbs + tbsign_len + octet_len, signalgid_data, signalgid_len);
#else
        SESv2_SealSignRange calc_sign;
        calc_sign.sealinfo = sealinfo;
        calc_sign.cert = signinfo->cert;
        calc_sign.signalgid = signinfo->signalgid;
        unsigned char *tbsign_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_tbsign_der(nullptr, &Openssl_deleter);
        int tbsign_len = i2d_SESv2_SealSignRange(&calc_sign, &tbsign_der);
        guard_tbsign_der.reset(tbsign_der);
        if (tbsign_len < 0) {
          return m_error = ErrInvalidTBSign;
        }

#endif
        auto signed_value = ASN1_STRING_get0_data(signinfo->signedvalue);
        auto signed_value_len = ASN1_STRING_length(signinfo->signedvalue);

        EVP_CUNSTOM evp;
        evp.pkey = X509_get_pubkey(m_seal_maker_cert.get());
        unsigned char *pkey_der = NULL;
        std::unique_ptr<unsigned char, decltype(&Openssl_deleter)> guard_pkey_der(nullptr, &Openssl_deleter);
        int der_len = i2d_PUBKEY(evp.pkey, &pkey_der);
        guard_pkey_der.reset(pkey_der);
        if (der_len <= 0)
        {
          return m_error = ErrNoPubKey;
        }
        sm2PublicKey sm2verify(pkey_der, der_len);
        std::string errmsg;
        if (!sm2verify.SignatureVerification(signed_value, signed_value_len, tbsign_der, tbsign_len, errmsg)) {
          return m_error = ErrSealSignedValuCheckFailed;
        }
        return 0;
      }
}//end of namespace