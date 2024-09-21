
#include "hare_define.h"

#ifndef __HARE_LIBRARY_H__
#define __HARE_LIBRARY_H__


typedef struct hare_library_s hare_library;

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>libhare库初始化</b></tt>
/// @param[in]	loadfont 是否加载字体库(渲染和转换需要字体库)
/// @param[in]	loadfont 是否关闭控制台日志输出(渲染和转换需要字体库)
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION long hare_library_init(int load_font, const char *machine_code, const char *lic_code);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>libhare库资源释放</b></tt>
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION long hare_library_release();

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>设置文档解析附加字体路径</b></tt>
/// @param[in]	font_path 字体文件夹路径
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION long hare_library_set_font_path(const char *font_path);


/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>获取libhare库版本</b></tt>
/// @return		版本号字符串(eg:"1.0.0.72")
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION const char* hare_library_get_version();


/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>关闭breakpad功能</b></tt>
/// @return		无
/// @note       测试过程中发现jni使用breakpad会使jvm崩溃
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION void hare_library_turnoff_breakpad();

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>关闭breakpad崩溃转储存放的地址</b></tt>
/// @return		无
/// @note       
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION void hare_library_dump_location(const char *path);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>pdf转ofd</b></tt>
/// @param[in]	src_fpath pdf文件路径
/// @param[in]	dst_fpath ofd文件路径
/// @param[in]  page_range 指定要转换的页信息；单页："1"，指定页使用逗号分隔：如"1,3,6"，A-N:转换A至N页，如："2-3"，*或NULL：转换全部页
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_pdf2ofd(const char *src_fpath, const char *dst_fpath, const char *page_range);
HARE_FUNCTION
long hare_library_pdf2ofd_with_data(const unsigned char* src_data, unsigned int src_data_len, unsigned char** out_data, unsigned int* out_data_len, const char* page_range);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>ofd转pdf</b></tt>
/// @param[in]	src_fpath ofd文件路径
/// @param[in]	dst_fpath pdf文件路径
/// @param[in]  page_range 指定要转换的页信息；单页："1"，指定页使用逗号分隔：如"1,3,6"，A-N:转换A至N页，如："2-3"，*或NULL：转换全部页
/// @param[in]  existing_tempath 一个已存在的临时目录用于文字裁剪中间文件
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_ofd2pdf(const char *src_fpath, const char *dst_fpath, const char *page_range, const char *existing_tempath);
HARE_FUNCTION
long hare_library_ofd2pdf_with_data(const unsigned char* src_data, unsigned int src_data_len, unsigned char** out_data, unsigned int* out_data_len, const char* page_range, const char* existing_tempath);

//////////////////////////////////////////////////////////////////////////
// @brief      <tt><b> 创建空白文档 </b></tt>
// @param[in]  doctype 文档类型（0:OFD，1:PDF）
// @param[in]  (x0,y0) 媒体框的左上角坐标（单位：mm）
// @param[in]  (x1,y1) 媒体框的右下角坐标（单位：mm）
// @param[out] doc 文档句柄
// @return     错误码，参见\link HARE_ERRORcode_def.h\endlink
HARE_FUNCTION
long hare_library_create_document(void** doc, int doctype, int x0, int y0, int x1, int y1);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>打开mupdf支持的文件</b></tt>
/// @param[in]	src_fpath 文件路径
/// @param[in]	ext 扩展名
/// @return		doc, 文档句柄
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
void* hare_library_open_document(const char *src_fpath, const char *ext);
HARE_FUNCTION
void* hare_library_open_document_with_data(const unsigned char* src_data, unsigned int src_data_len);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>关闭hare_library_open_document 打开的文档</b></tt>
/// @param[in]	doc 文档句柄
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_close_document(const void *doc);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>保存文档</b></tt>
/// @param[in]	doc 文档句柄
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_save_document(const void* doc);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>文档另存为</b></tt>
/// @param[in]	doc 文档句柄
/// @param[in]	dst_path 文件路径
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_save_as_document(const void* doc, const char* dst_path);
HARE_FUNCTION
long hare_library_save_as_buffer(const void* doc, unsigned char** out_buffer, unsigned int* out_buffer_len);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>获取打开的文档页数</b></tt>
/// @param[in]	doc 文档句柄
/// @return		文档页数
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_doc_pages(const void *doc);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief     <tt><b>获取页面图像</b></tt>
/// @param[in] hare_doc 文档句柄
/// @param[in] image_fpath 获取图像的保存路径绝对路径
/// @param[in] page_no 页面的页码，从1开始
/// @param[in] image_format null 为默认png, 支持 png,jpeg,jpg,svg,tga,pam,pnm,pgm,ppm,pbm,pkm
/// @param[in] options, 详解如下： 
/// "Common raster format output options:\n"
/// "rotate=N: rotate rendered pages N degrees counterclockwise\n"
/// "resolution=N: set both X and Y resolution in pixels per inch\n"
/// "x-resolution=N: X resolution of rendered pages in pixels per inch\n"
/// "y-resolution=N: Y resolution of rendered pages in pixels per inch\n"
/// "width=N: render pages to fit N pixels wide (ignore resolution option)\n"
/// "height=N: render pages to fit N pixels tall (ignore resolution option)\n"
/// "colorspace=(gray|rgb|cmyk): render using specified colorspace\n"
/// "alpha: render pages with alpha channel and transparent background\n"
///	"SVG output options:\n"
/// "text=text: Emit text as <text> elements (inaccurate fonts).\n"
/// "text=path: Emit text as <path> elements (accurate fonts).\n"
/// "no-reuse-images: Do not reuse images using <symbol> definitions.\n"
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_get_page_image(void *hare_doc, const char *image_fpath, int page_no, const char *image_format/*null means png*/, const char *options/*NULL for default*/);
HARE_FUNCTION
long hare_library_get_multi_page_image(void *hare_doc, const char *image_dir, const char* page_info, const char *image_format/*null means png*/, const char *options/*NULL for default*/);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief     <tt><b>获取页面图像字节流</b></tt>
/// @param[in] hare_doc 文档句柄
/// @param[out] out_data 图像字节流
/// @param[out] out_data_len 图像字节流长度
/// @param[out] page_count 页面图像数量
/// @param[in] page_no 页面的页码，从1开始
/// @param[in] image_format null为默认png, 仅支持png,jpeg,jpg
/// @param[in] options, 详解如下： 
/// "Common raster format output options:\n"
/// "rotate=N: rotate rendered pages N degrees counterclockwise\n"
/// "resolution=N: set both X and Y resolution in pixels per inch\n"
/// "x-resolution=N: X resolution of rendered pages in pixels per inch\n"
/// "y-resolution=N: Y resolution of rendered pages in pixels per inch\n"
/// "width=N: render pages to fit N pixels wide (ignore resolution option)\n"
/// "height=N: render pages to fit N pixels tall (ignore resolution option)\n"
/// "colorspace=(gray|rgb|cmyk): render using specified colorspace\n"
/// "alpha: render pages with alpha channel and transparent background\n"
///	"SVG output options:\n"
/// "text=text: Emit text as <text> elements (inaccurate fonts).\n"
/// "text=path: Emit text as <path> elements (accurate fonts).\n"
/// "no-reuse-images: Do not reuse images using <symbol> definitions.\n"
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
HARE_FUNCTION
long hare_library_get_page_image_with_data(void *hare_doc, unsigned char** out_data, unsigned int* out_data_len, int page_no, const char *image_format/*null means png*/, const char *options/*NULL for default*/);
HARE_FUNCTION
long hare_library_get_multi_page_image_with_data(void *hare_doc, unsigned char*** out_data, unsigned int** out_data_len, unsigned int* page_count, const char* page_info, const char *image_format/*null means png*/, const char *options/*NULL for default*/);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief     <tt><b>获取页面尺寸</b></tt>
/// @param[in] doc 文档句柄
/// @param[in] type:
///   type=0    //媒体框-ofd::PhysicalBox，pdf::MediaBox
///   type=1    //裁剪框-ofd::ApplicationBox，pdf::CropBox	
///   type=2    //出血框-ofd::BleedBox，pdf::BleedBox
///   type=3    //裁切框-ofd::ContentBox，pdf::TrimBox
///   type=4    //作品框-pdf::ArtBox
/// @param[in] do_trans do_trans_rect=0取原始的页面rect，do_trans_rect=1取旋转且原点变换后的页面rect
/// @param[out] x0, 页面矩形的左上角坐标
/// @param[out] y0
/// @param[out] x1   页面矩形的右下角坐标
/// @param[out] y1
HARE_FUNCTION
long hare_library_get_page_box(const void *doc, int type, long pageno, int do_trans, float *x0, float *y0, float *x1, float *y1);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>从文档中删除某一页</b></tt>
/// @param[in]	doc 文档句柄
/// @param[in]	pageno 要删除页的页号(从1开始)
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_delete_page(const void* doc, long pageno);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief      <tt><b>从文件中插入指定页到文档中去</b></tt>
/// @param[in]  doc 文档句柄
/// @param[in]  file_path 要被插入到文档中去的文件路径,支持的文件类型就是转换支持的类型
/// @param[in]	page_info 指定要插入的页信息；单页："1"，指定页使用逗号分隔：如"1,3,6"，A-N:插入A至N页，如："2-3"，*或NULL：插入全部页
/// @param[in]	pageno 要插入页的页号(从1开始)
/// @return     错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_insert_page_from_file(const void* doc, const char* file_path, const char* page_info, long pageno);
HARE_FUNCTION
long hare_library_insert_page_from_doc(const void* doc, const void* src, const char* page_info, long pageno);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief      <tt><b>合并两个版式文件</b></tt>
/// @param[in]  dst 目标ofd文件，全路径，utf8编码
/// @param[in]  src 要被合并入dst的源文件，全路径，utf8编码
/// @param[in]  page_info 要被合并到文档中去的指定的页信息；单页："1"，指定页使用逗号分隔：如"1,3,6"，A-N:合并A至N页，如："2-3"，*或NULL：合并全部页
/// @param[in]  pageno 要插入页的页号(从1开始), 负数表示在文件尾追加
/// @return     错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_combine_document(const char* dst, const char* src, const char* page_info, long pageno);
HARE_FUNCTION
long hare_library_combine_document_with_data(const unsigned char* dst_data, unsigned int dst_data_len, const unsigned char* src_data, unsigned int src_data_len, const char* page_info, long pageno, unsigned char** out_data, unsigned int* out_data_len);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief      <tt><b>提取指定文档页另存为新文档</b></tt>
/// @param[in]  src	源文件路径，UTF-8编码
/// @param[in]	dst	目标文件路径，UTF-8编码
/// @param[in]	ext	src文件扩展名
/// @param[in]  page_info 指定要提取的页信息；单页："1"，指定页使用逗号分隔：如"1,3,6"，A-N:提取A至N页，如："2-3"，*或NULL：提取全部页
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_extract_document_page(const char* src, const char* dst, const char* ext, const char* page_info);
HARE_FUNCTION
long hare_library_extract_document_page_with_data(const unsigned char* src_data, unsigned int src_data_len, unsigned char** out_data, unsigned int* out_data_len, const char* page_info);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief      <tt><b>获取设备机器码</b></tt>
/// @param[out]	buffer	机器码
/// @param[in]	buffer_size	buffer的长度，至少为33
/// @return
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
void hare_library_machine_identifier(char* buffer, size_t buffer_size);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>ofd模板生成ofd</b></tt>
/// @param[in]	tpl ofd模板文件流
/// @param[in]	tpl_len 文件流大小
/// @param[in]	data 数据流
/// @param[in]	data_size 数据流大小
/// @param[out]	out_data ofd文件流
/// @param[out]	out_size ofd文件流大小
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_create_ofd_data(const unsigned char* tpl, const unsigned int tpl_size, const unsigned char* data, const unsigned int data_size, unsigned char** out_data, unsigned int* out_size);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>pdf建立签名域等签名基础结构，ofd建立signature.xml等基础结构，然后获取待签名文档的摘要值</b></tt>
/// @param[in]	doc 文档句柄
/// @param[in]	img 印膜图片
/// @param[in]	img_len 印膜图片大小
/// @param[in]	digest_method摘要计算算法，目录只支持sm3, 1.2.156.10197.1.401
/// @param[in] px_x, px_y	单位px 签章左上角的坐标
/// @param[in] mm_w, mm_h 签章宽高，单位mm
/// @param[in] pageno	盖章文档页号(从1开始)
/// @param[out]  out_digest 计算的文档摘要值
/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/// @note   文档签章流程：
///  调用者从signature_provider 获取印膜（电子印章：pdf/ofd其实都可以不要电子印章，pdf本身不要，ofd的esl文件也是可以缺省的）
///  调用者调用hare_library_calc_sign_digest 类接口 计算出文档待签名摘要值
///  调用者调用hare_library_write_sign_value接口，将签章结构体写入文档中。
///  hare_library_calc_**_digest 与 hare_library_write_sign_value 需成对使用，即使取了摘要值由于其它原因中断签署也需调用hare_library_write_sign_value 并设置取消状态
///  hare_library_calc_**_digest 与 hare_library_write_sign_value调用之间不能插入其它调用，文件的修改在库内被冻结
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_calc_sign_digest(const void *doc, unsigned char *img, unsigned int img_len, char* digest_method, int px_x, int px_y, float mm_w, float mm_h, unsigned int pageno, unsigned char out_digest[32]);

/////////////////////////////////////////////////////////////////////////////////////
/// @brief		<tt><b>将签名值 写到hare_library_calc_sign_digest 创建的签名域（pdf)/signature.dat(ofd)中，完成一次签名流程</b></tt>
/// @param[in]	doc 文档句柄
/// @param[in]	signed_value 签名数据
/// @param[in]	vlen 签名数据长度

/// @return		错误码，参见\link HARE_ERRORcode_def.h\endlink
/// @note   文档签章流程：
///  调用者从signature_provider 获取印膜（电子印章：pdf/ofd其实都可以不要电子印章，pdf本身不要，ofd的esl文件也是可以缺省的）
///  调用者调用hare_library_calc_sign_digest 类接口 计算出文档待签名摘要值
///  调用者调用hare_library_write_sign_value接口，将签章结构体写入文档中。
///  hare_library_calc_**_digest 与 hare_library_write_sign_value 需成对使用，即使取了摘要值由于其它原因中断签署也需调用hare_library_write_sign_value 并设置取消状态
/////////////////////////////////////////////////////////////////////////////////////
HARE_FUNCTION
long hare_library_write_sign_value(const void *doc, unsigned char * signed_value, unsigned int vlen);
#ifdef __cplusplus
}
#endif

#endif //__HARE_LIBRARY_H__
