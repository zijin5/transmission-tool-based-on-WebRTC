#ifndef PROTOZOA_HOOKS_H_
#define PROTOZOA_HOOKS_H_

#include <string.h>
#include <string>
#include <mutex>
//外部的
#include "macros.h"
//打印帧数据，接受一个 uint8_t 类型的帧缓冲区和一个整型的帧长度作为参数。
void printFrameData(uint8_t* frame_buffer, int frame_length);
//打印编码图像信息，接受编码宽度、编码高度、编码长度、编码大小、是否完整帧、量化参数、帧类型、帧缓冲区和一个布尔值作为参数。
void printEncodedImageInfo(uint32_t encodedWidth, uint32_t encodedHeight, size_t length, size_t size, bool completeFrame, int qp, int frameType, uint8_t* buffer, bool printBuffer);
//将数据编码到帧缓冲区，接受一个 uint8_t 类型的帧缓冲区、一个整型的帧长度和一个分区偏移量作为参数。
void encodeDataIntoFrame(uint8_t* frame_buffer, int frame_length, int dct_partition_offset);
//从帧缓冲区中检索数据，接受一个 uint8_t 类型的帧缓冲区、一个整型的帧长度和一个分区偏移量作为参数。
void retrieveDataFromFrame(uint8_t* frame_buffer, int frame_length, int dct_partition_offset);
//打印字符串消息，接受一个字符串作为参数。
void probePrint(std::string msg);
// 从管道读取数据。
void readFromPipe();
//静态内联函数GetBitsAt，用于获取给定数据的指定位偏移量上的一定数量位数的值。
//1 << num_bits) - 1	：指定获取的
static inline uint32_t GetBitsAt(uint32_t data, size_t shift, size_t num_bits) {
  return ((data >> shift) & ((1 << num_bits) - 1));
}

#endif //PROTOZOA_HOOKS_H_
