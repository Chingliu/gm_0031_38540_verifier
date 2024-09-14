#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <openssl/ssl.h> 

#include <openssl/asn1.h>
#include <openssl/err.h>
#include "38540.h"  // 包含上述定义的所有结构体和 ASN1 序列声明

// 函数声明
int decode_signature(const unsigned char *data, long data_len);

int main() {
#if 0
  /* SSL 库初始化*/
  SSL_library_init();
  /* 载入所有SSL 算法*/
  OpenSSL_add_all_algorithms();
  /* 载入所有SSL 错误消息*/
  SSL_load_error_strings();
  // 初始化 OpenSSL 加密库
  if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, NULL)) {
    fprintf(stderr, "Failed to initialize OpenSSL\n");
    return 1;
  }
#endif

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
  // 调用解析函数
  int result = decode_signature(binary_data, binary_data_len);
  if (result < 0) {
    printf("Failed to decode signature\n");
    return -1;
  }

  return 0;
}


int decode_signature(const unsigned char *data, long data_len) {
  const unsigned char *p = data;


  SESv4_Signature * v4sign = NULL;
  SESv2_Signature * sign = d2i_SESv2_Signature(NULL, &p, data_len);
  if (!sign){
    unsigned long err = ERR_get_error();
    char err_msg[256];
    ERR_error_string_n(err, err_msg, sizeof(err_msg));
    printf(err_msg);
    p = data;
    v4sign = d2i_SESv4_Signature(NULL, &p, data_len);
    if (!v4sign)
    {
      err = ERR_get_error();
      ERR_error_string_n(err, err_msg, sizeof(err_msg));
      printf(err_msg);
    }
  }


  if(sign){
    SESv2_Signature_free(sign);
  }
  if (v4sign)
  {
    SESv4_Signature_free(v4sign);
  }
  return 0;
}
