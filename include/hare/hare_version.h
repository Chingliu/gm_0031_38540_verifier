
#ifndef __HARE_VERSION_H__
#define __HARE_VERSION_H__

#define VERSION_MJR		 1							//!< 主版本号
#define VERSION_MIN		 0							//!< 次版本号
#define VERSION_UPDATE	 0							//!< 分支版本号
#define VERSION_BUILD	 3							//!< 构建版本号
#define VERSION_RELEASE  0							//!< 发行版本号
#define VERSION_DATE	 20240814					//!< 发行日期

#define __STR__(s)     #s
#define MACRO2STR(s)   __STR__(s)
#define VERSION_STR(a,b,c,d) a##.##b##.##c##.##d	//!< 版本号字符串
#define VERSION_STR2(a,b) a##.##b					//!< 版本号字符串

#endif //__HARE_VERSION_H__
