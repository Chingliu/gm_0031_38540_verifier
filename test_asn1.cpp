#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ssl.h> 
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <time.h>
#include "38540.h"  // 包含上述定义的所有结构体和 ASN1 序列声明
#include <vector>
#include "sm2sign.h"
#include "hare/hare_library.h"
// 函数声明
int decode_signature(const unsigned char *data, long data_len);

void digestsign();

// 从证书提取时间并转换为 ASN1_GENERALIZEDTIME
ASN1_GENERALIZEDTIME *convert_to_generalizedtime(ASN1_TIME *time) {
  ASN1_GENERALIZEDTIME *genTime = ASN1_GENERALIZEDTIME_new();
  if (!ASN1_TIME_to_generalizedtime(time, &genTime)) {
    fprintf(stderr, "Error converting time to generalized time\n");
    ASN1_GENERALIZEDTIME_free(genTime);
    return NULL;
  }
  return genTime;
}

int main() {
  CGuardOpenssl openssl_resource_guard;

  auto lic = hare_library_init(1, "", "eoCw5vwwkSnpnaNoLCHhRDdFM2JtY0l5MVE1NWR1bjNSWXM5OU1UNTVuRW1ub3KJKFSWrG+CwqiPn5kOtubnRD/NAZ7DbfQMdtEEeXqiKMZDCXa0kgQJsRYap2vxBRmKhxv2GQqqGfTe9kLB7ukPXUKJp6xZf26S/AZh4HUJloglN/hUJrvH+DNfX1tbZ2vSyBgULdLQktDlB7/LiCbW80W4Y6Iuahe9QsoLx3LrU6ChKKdnDYM3q/KziaESheNZv1baFPTHkNskeA3l7vOocsAEmz8kwVc8Fbcl/7VO7bDxW0KIY/Eu93b0h5y6yMblNRCpBcZekX/zd6EFH5n8oA==");
  if (lic != 0)
  {
    printf("hare no lic");
    return -1;
  }
  auto hdoc = hare_library_open_document("d:\\tests\\19.pdf", ".pdf");
  if (!hdoc)
  {
    return -1;
  }
  unsigned char *binary_data = NULL;  // 从文件或其他来源获取的二进制数据
  long binary_data_len = 0;        // 二进制数据的长度
  FILE *fp = fopen("d:\\SignedValue.dat", "rb");
  //FILE *fp = fopen("d:\\tests\\38540.dat", "rb");
  if (fp)
  {
    binary_data = (unsigned char *)malloc(50 * 1024);
    binary_data_len = fread(binary_data, 1, 50 * 1024, fp);
    if (binary_data_len<= 0)
    {
      return -1;
    }

  }
#if 1
  // 调用解析函数
  int result = decode_signature(binary_data, binary_data_len);
  if (result < 0) {
    printf("Failed to decode signature\n");
    return -1;
  }
#endif
  CDigest sm3("sm3");
  std::string msg("hello sm3");
  sm3.digest_update((const unsigned char *)msg.c_str(), msg.length());
  unsigned char msg_digest[32];
  if (!sm3.get_digest(msg_digest)) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    std::string err;
    int iret = load_pfx_file("d:\\sm2_test.pfx", "123456", &pkey, &cert);
    sm2PrivateKey sign(pkey);
    auto signed_msg = sign.PkeySign(msg_digest);
    //TODO,进行38540封装
    //制章先？
    // 创建 SESv4_ESPropertyInfo 结构
    SESv4_ESPropertyInfo *info = SESv4_ESPropertyInfo_new();

    // 设置 certListType 为 1
    ASN1_INTEGER_set(info->certListType, 1);

    // 获取证书数据并添加到 certs 成员中
    unsigned char *cert_der = NULL;
    int cert_len = i2d_X509(cert, &cert_der);
    if (cert_len < 0) {
      fprintf(stderr, "Error converting cert to DER format\n");
      return -1;
    }
    info->certs = sk_ASN1_OCTET_STRING_new_null();
    ASN1_OCTET_STRING *cert_octet = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(cert_octet, cert_der, cert_len);
    sk_ASN1_OCTET_STRING_push(info->certs, cert_octet);
    

    // 设置 createDate 为当前时间
    info->createDate = ASN1_GENERALIZEDTIME_set(NULL, time(NULL));

    // 从证书中提取有效时间
    ASN1_TIME *notBefore = X509_getm_notBefore(cert);
    ASN1_TIME *notAfter = X509_getm_notAfter(cert);

    // 转换时间并设置 validStart 和 validEnd
    info->validStart = convert_to_generalizedtime(notBefore);
    info->validEnd = convert_to_generalizedtime(notAfter);


    // 创建并初始化 SESv4_SealInfo
    SESv4_SealInfo *sealInfo = SESv4_SealInfo_new();

    // 设置 SESv4_SealInfo 的 property 成员
    sealInfo->property = info;

    SES_Header * es_header = SES_Header_new();
    es_header->id = ASN1_IA5STRING_new();
    ASN1_STRING_set(es_header->id, "ES", strlen("ES"));
    // 设置 version 为 4
    es_header->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(es_header->version, 4);

    // 设置 vid 为 "hare"
    es_header->vid = ASN1_IA5STRING_new();
    ASN1_STRING_set(es_header->vid, "hare", strlen("hare"));
    sealInfo->header = es_header;

    sealInfo->esid = ASN1_IA5STRING_new();
    ASN1_STRING_set(sealInfo->esid, "hare_testing_seal", strlen("hare_testing_seal"));

    SES_ESPictureInfo* es_picture = SES_ESPictureInfo_new();
    es_picture->type = ASN1_IA5STRING_new();
    ASN1_STRING_set(es_picture->type, "png", strlen("png"));

    std::vector<unsigned char > fcontent;
    long fsize = 0;
    {
      FILE *fp = fopen("d:\\Image_5856.png", "rb");
      if (fp)
      {
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        fcontent.resize(fsize);
        auto read = fread(&fcontent[0], 1, fsize, fp);
        if (read != fsize)
        {
        }
        es_picture->data = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(es_picture->data, &fcontent[0], fsize);
      }
    }
    ASN1_INTEGER_set(es_picture->width, 40);
    ASN1_INTEGER_set(es_picture->height, 40);

    sealInfo->picture = es_picture;

    SESv4_Seal * seal = SESv4_Seal_new();
    seal->sealinfo = sealInfo;
    seal->cert = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(seal->cert, cert_der, cert_len);

    {
      const char *sm2_oid = "1.2.156.10197.1.501";
      seal->signalgid = OBJ_txt2obj(sm2_oid, 1);
      unsigned char *seal_info_der = NULL;
      int seal_info_len = i2d_SESv4_SealInfo(sealInfo, &seal_info_der);
      if (seal_info_len < 0) {
        fprintf(stderr, "Error converting cert to DER format\n");
        return -1;
      }
      
#if 0 //TODO需要的是sm3withsm2
      CDigest seal_digest("sm3");
      seal_digest.digest_update(seal_info_der, seal_info_len);
      OPENSSL_free(seal_info_der);
      unsigned char seal_md[32];
      if (seal_digest.get_digest(seal_md)) {
        return -1;
      }
      auto seal_signed = sign.PkeySign(seal_md);
      if (seal_signed.empty())
      {
        return -1;
      }
#else
      std::string errmsg;
      auto seal_signed = sign.Signature(seal_info_der, seal_info_len, errmsg);
      if (seal_signed.empty())
      {
        return -1;
      }
#endif 
      OPENSSL_free(seal_info_der);
      seal->signedvalue = ASN1_BIT_STRING_new();
      ASN1_BIT_STRING_set(seal->signedvalue, &seal_signed[0], seal_signed.size());
    }

    TBSv4_Sign *tb_sign = TBSv4_Sign_new();
    ASN1_INTEGER_set(tb_sign->version, 4);
    tb_sign->eseal = seal;
    tb_sign->timeinfo = ASN1_GENERALIZEDTIME_set(NULL, time(NULL));
    {
      unsigned char  doc_digest[32];
      long lret = hare_library_calc_sign_digest(hdoc, &fcontent[0], fsize, (char *)"sm3", 100, 100, 40, 40, 1, doc_digest);
      if (lret != 0)
      {
        return -1;
      }
      tb_sign->datahash = ASN1_BIT_STRING_new();
      ASN1_BIT_STRING_set(tb_sign->datahash, doc_digest, 32);
    }
    tb_sign->propertyinfo = ASN1_IA5STRING_new();
    ASN1_STRING_set(tb_sign->propertyinfo, "d:\\tests\19.pdf", strlen("d:\\tests\19.pdf"));

    SESv4_Signature *doc_sign = SESv4_Signature_new();
    doc_sign->tosign = tb_sign;
    doc_sign->cert = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(doc_sign->cert, cert_der, cert_len);
    {
      const char *sm2_oid = "1.2.156.10197.1.501";
      doc_sign->signalgid = OBJ_txt2obj(sm2_oid, 1);

      unsigned char *tbsign_der = NULL;
      int tbsign_len = i2d_TBSv4_Sign(tb_sign, &tbsign_der);
      if (tbsign_len < 0) {
        fprintf(stderr, "Error converting cert to DER format\n");
        return -1;
      }
#if 0      //TODO需要的是sm3withsm2
      CDigest tb_digest("sm3");
      tb_digest.digest_update(tbsign_der, tbsign_len);
      OPENSSL_free(tbsign_der);
      unsigned char tb_md[32];
      if (tb_digest.get_digest(tb_md)) {
        return -1;
      }
      auto tb_signed = sign.PkeySign(tb_md);
      if (tb_signed.empty())
      {
        return -1;
      }
#else
      std::string  errmsg;
      auto tb_signed = sign.Signature(tbsign_der, tbsign_len, errmsg);
      if (tb_signed.empty())
      {
        return -1;
      }
#endif
      OPENSSL_free(tbsign_der);
      doc_sign->signedvalue = ASN1_BIT_STRING_new();
      ASN1_BIT_STRING_set(doc_sign->signedvalue, &tb_signed[0], tb_signed.size());
    }

    {
      unsigned char* sign_data = nullptr;
      auto sign_data_len = i2d_SESv4_Signature(doc_sign, &sign_data);
      if (sign_data_len < 0)
      {
        return -1;
      }
      hare_library_write_sign_value(hdoc, sign_data, sign_data_len);
      OPENSSL_free(sign_data);
    }

    SESv4_Signature_free(doc_sign);
    OPENSSL_free(cert_der);
    //TODO,将38540封装数据写入pdf/ofd
    sm2PublicKey verify = sign.CreatePublic();
    //verify.SignatureVerification(signed_msg, msg, err);
    verify.PkeyVerification(signed_msg, msg_digest);
    printf("verfied message: %s", err.c_str());
  }
  return 0;
}
void digestsign() {
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  int iret = load_pfx_file("d:\\sm2_test.pfx", "123456", &pkey, &cert);

  sm2PrivateKey sign(pkey);
  std::string msg = "hello openssl";
  std::string err;
  auto signed_msg = sign.Signature((const unsigned char *)msg.c_str(), msg.length(), err);
  sm2PublicKey verify = sign.CreatePublic();

  verify.SignatureVerification(signed_msg, msg, err);
  printf("verfied message: %s", msg.c_str());
}

int decode_signature(const unsigned char *data, long data_len) {

  gm::C0031 v2sign(data, data_len);
  if (v2sign.data_parsed()) {
    printf("it is 0031 sign");
    v2sign.sign_verify((unsigned char *)"test", 4);
  }
  gm::C38540 v4sign(data, data_len);
  if (v4sign.data_parsed())
  {
    printf("it is 38540 sign");
    v4sign.sign_verify((unsigned char *)"test", 4);
  }


  return 0;
}
