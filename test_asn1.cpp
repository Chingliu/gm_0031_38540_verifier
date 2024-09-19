#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <openssl/ssl.h> 

#include <openssl/asn1.h>
#include <openssl/err.h>
#include "38540.h"  // 包含上述定义的所有结构体和 ASN1 序列声明

#include "sm2sign.h"
// 函数声明
int decode_signature(const unsigned char *data, long data_len);
int sm3_sm2();
void digestsign();
int main() {
  CGuardOpenssl openssl_resource_guard;

  unsigned char *binary_data = NULL;  // 从文件或其他来源获取的二进制数据
  long binary_data_len = 0;        // 二进制数据的长度
  //FILE *fp = fopen("d:\\SignedValue.dat", "rb");
  FILE *fp = fopen("d:\\tests\\38540.dat", "rb");
  if (fp)
  {
    binary_data = (unsigned char *)malloc(50 * 1024);
    binary_data_len = fread(binary_data, 1, 50 * 1024, fp);
    if (binary_data_len<= 0)
    {
      return -1;
    }

  }
#if 0
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
  auto signed_msg = sign.Signature(msg, err);
  sm2PublicKey verify = sign.CreatePublic();

  verify.SignatureVerification(signed_msg, msg, err);
  printf("verfied message: %s", msg.c_str());
}

int decode_signature(const unsigned char *data, long data_len) {

  gm::C0031 v2sign(data, data_len);
  if (v2sign.data_parsed()) {
    printf("it is 0031 sign");
  }
  gm::C38540 v4sign(data, data_len);
  if (v4sign.data_parsed())
  {
    printf("it is 38540 sign");
  }


  return 0;
}
