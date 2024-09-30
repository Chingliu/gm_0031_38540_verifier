
#ifndef __HARE_DEFINE_H__
#define __HARE_DEFINE_H__


#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARECRYPTO_API
#if defined(_WIN32)
	#include <Windows.h>

	#pragma warning(disable:4290)
	#pragma warning(disable:4244)

  #if defined(_WIN32)
		#ifdef HARECRYPTO_EXPORT
			#define HARECRYPTO_API __declspec(dllexport)
		#else
			#define HARECRYPTO_API
		#endif

	#else
		#define HARECRYPTO_API
	#endif

#else
	#if defined (__GNUC__)
		#define HARECRYPTO_API __attribute__((visibility("default")))

	#else
		#define HARECRYPTO_API
	#endif
#endif //_WINDOWS
#endif

#ifdef __cplusplus
extern "C" {
#endif
  /////////////////////////////////////////////////////////////////////////////////////
  /// @brief      <tt><b>构建签章结构</b></tt>
  /// @param[in]	data 签章数据，暂时只支持0031/38540
  /// @param[in]	len
  /// @return  签章句柄，需调用hare_crypto_sign_free释放
  /////////////////////////////////////////////////////////////////////////////////////
  HARECRYPTO_API void * hare_crypto_sign_new(const unsigned char *data, long len);

  /////////////////////////////////////////////////////////////////////////////////////
  /// @brief      <tt><b>释放签章句柄所占资源</b></tt>
  /// @param[in]	psign 签章句柄， hare_crypto_sign_new的返回值
  /// @return  
  /////////////////////////////////////////////////////////////////////////////////////
  HARECRYPTO_API void hare_crypto_sign_free(void *psign);

  /////////////////////////////////////////////////////////////////////////////////////
  /// @brief      <tt><b>获取签章的摘要算法</b></tt>
  /// @param[in]	psign 签章句柄， hare_crypto_sign_new的返回值
  /// @return  签章所用的摘要算法，返回值调用者无需管理内存，由psign管理
  /////////////////////////////////////////////////////////////////////////////////////
  HARECRYPTO_API char * hare_crypto_sign_digest_method(const void *psign);
  /////////////////////////////////////////////////////////////////////////////////////
  /// @brief      <tt><b>签章验证</b></tt>
  /// @param[in]  psign 签章句柄， hare_crypto_sign_new的返回值
  /// @param[in]	digest，待验证原文的摘要
  /// @param[in]	digest_len
  /// @return  0是验证成功， 其它验证失败
  /////////////////////////////////////////////////////////////////////////////////////
  HARECRYPTO_API int hare_crypto_sign_verify(const void *psign, const unsigned char * digest, long digest_len);
#ifdef __cplusplus
}
#endif


#endif //__HARE_DEFINE_H__
