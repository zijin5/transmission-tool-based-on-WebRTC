#include "protozoa_hooks.h"
#include <iostream>//用于输入和输出，包括 cin、cout、cerr 等流对象。
#include <fstream>//用于文件输入和输出，包括 ifstream、ofstream 等文件流对象。
#include <string>//用于字符串操作，包括字符串的创建、连接、查找、替换等操作。
#include <vector>//用于动态数组，可以方便地进行元素的插入、删除、访问等操作。
#include <mutex>//用于多线程同步，提供了锁的机制，以保证多线程访问共享数据的安全。
#include <queue>//用于队列操作，可以方便地进行队列的插入、删除等操作。
#include <chrono>//用于时间和日期操作，包括时间点的获取、时间间隔的计算、时间格式化等操作。
#include <unistd.h>//用于 Unix 操作系统的系统调用，包括 read、write、close、pipe 等。
#include <fcntl.h>//用于 Unix 操作系统的文件控制操作，包括 open、fcntl 等。
#include <iostream>//与第一个 iostream 头文件的作用相同，用于输入和输出。

std::string protozoa_decoder_pipe = "/tmp/protozoa_decoder_pipe";
int decoder_fd = open(protozoa_decoder_pipe.c_str(), O_WRONLY | O_NONBLOCK);

std::string protozoa_encoder_pipe = "/tmp/protozoa_encoder_pipe";
int encoder_fd = open(protozoa_encoder_pipe.c_str(), O_RDONLY | O_NONBLOCK);
//存储完整的IP数据包，每个元素都是一个固定长度的，包含完整IP数据内容的vector<uint8_t>类型的向量
//Queue for holding outbound IP packets
std::deque<std::vector<uint8_t>> staging_queue;
//存储IP数据包的分片数据，每个元素都是一个长度不固定，包含IP数据包分片内容的vector<unit8_t>类型的向量
//Queue for holding outbound IP packet fragments
std::deque<std::vector<uint8_t>> staging_queue_fragments;


//Debug flag
int debug = 0;
//网络拥塞，队列内容不超过24，根据RTT往返时延和BW带宽有关
//Limit of queue size following the Size = RTT * BW rule of thumb
unsigned long queue_limit = 24;

//Length of Protozoa message header
int HEADER_LEN = 8;
//这段代码是为了设置一个最小的帧数据负载大小（MIN_PAYLOAD_SIZE），以确保在嵌入数据时帧数据具有足够的空间来存储它。当帧的有效负载（不包括帧头和校验和）小于 MIN_PAYLOAD_SIZE 时，将不会将数据嵌入帧数据中。
//// Set minimum amount of bytes that a frame must have for us to embed data
const int MIN_PAYLOAD_SIZE = 20;


//管道错误信息
void checkPipeError(int err) {
    if (err == EAGAIN || err == EWOULDBLOCK){
        std::cout << "EAGAIN" << std::endl;
    }
    else if (err == EBADF){
        std::cout << "EBADF" << std::endl;
    }
    else if (err == EFAULT){
        std::cout << "EFAULT" << std::endl;
    }
    else if (err == EFBIG){
        std::cout << "EFBIG" << std::endl;
    }
    else if (err == EINTR){
        std::cout << "EINTR" << std::endl;
    }
    else if (err == EINVAL){
        std::cout << "EINVAL" << std::endl;
    }
    else if (err == EIO){
        std::cout << "EIO" << std::endl;
    }
    else if (err == EPIPE){
        std::cout << "EPIPE" << std::endl;
    }
}

//诊断是否到达某一位置
void probePrint(std::string msg) {
    std::cout << "Hello! I'm just a probe at " << msg << "!" << std::endl;
}

/// <summary>
/// 打印帧数据，接受一个 uint8_t 类型的帧缓冲区和一个整型的帧长度作为参数。
/// </summary>
/// <param name="frame_buffer"></param>
/// <param name="frame_length"></param>
void printFrameData(uint8_t* frame_buffer, int frame_length){
    //// [DEBUG] Print 1st and last 30 bytes of data written to pipe 打印输出管道的数据的前30个字节和后30个字节
    for (int i = 0; i < 30; i++)
        //两位十六进制的格式进行输出
        printf("0x%02x ", frame_buffer[i]);

    printf(" ... ");

    for (int i = frame_length - 30; i < frame_length; i++)
        printf("0x%02x ", frame_buffer[i]);
    printf("\n");
}

//解析帧头并打印前30个字节和二进制表示
void parseFrameHeader(uint8_t* frame_buffer){
    //// [DEBUG] Print 1st 30 bytes of data in a frame (hex and binary notation)
    for (int i = 0; i < 30; i++)
        printf("0x%02x ", frame_buffer[i]);
    printf("\n");

    for (int i = 0; i < 30; i++)
        std::cout << std::bitset<8>(frame_buffer[i]) << " ";
    std::cout << std::endl << std::endl;
}

void logChannelUtilization(int frame_length, int dct_partition_size, int payload_used, std::chrono::duration<double, std::milli> duration, std::chrono::duration<double, std::milli> assemble_time){
    std::cout << "[chromium_log_channel_performance]|" << frame_length << "|" << dct_partition_size << "|" << payload_used << "|" << duration.count() << "|" << assemble_time.count() << std::endl;
}

void logPacketsInQueue(int packets_in_queue){
    std::cout << "-------------------------" << std::endl;
    std::cout << "[packet_queue_size]|" << packets_in_queue << std::endl;
}

void logPacketsSentInFrame(int packets_sent_in_frame){
    std::cout << "[packets_sent_in_frame]|" << packets_sent_in_frame << std::endl;
}

void logFragmentsSentInFrame(int fragments_sent_in_frame){
    std::cout << "[fragments_sent_in_frame]|" << fragments_sent_in_frame << std::endl;
}
//将读取到的编码管道中的数据填充到队列中:
//存储完整的IP数据包，每个元素都是一个固定长度的，包含完整IP数据内容的vector<uint8_t>类型的向量
//Queue for holding outbound IP packets
//std::deque<std::vector<uint8_t>> staging_queue;
void fillQueue(std::vector<uint8_t> staging_buffer){
    int slice_pos = 0;
    int ptr_pos = 0;
    uint16_t packet_size = ((uint16_t) staging_buffer[ptr_pos + 1] << 8) | staging_buffer[ptr_pos];

    while (packet_size > 0) {
        slice_pos = ptr_pos;
        ptr_pos += packet_size + HEADER_LEN;
        
        if (ptr_pos > (int) staging_buffer.size()) {
            break;
        }
        
        std::vector<uint8_t> pkt(&staging_buffer[slice_pos], &staging_buffer[ptr_pos]);
        
        staging_queue.push_back(pkt);
        //下一个要处理数据包的长度
        packet_size = ((uint16_t) staging_buffer[ptr_pos + 1] << 8) | staging_buffer[ptr_pos];
    }
}

//从编码管道中读取数据，并将数据暂时存储到一个缓冲区，等到缓冲区中的数量足够再将其填充到队列中
void readFromPipe(){
    int read_n_bytes = 4096;
    uint8_t read_buffer[read_n_bytes];
    std::vector<uint8_t> staging_buffer;

    std::chrono::duration<double, std::milli> read_time;
    auto start_read = std::chrono::high_resolution_clock::now();
	//从管道中读
    while(true){
        int nread = read(encoder_fd, &read_buffer, read_n_bytes);
        if(nread > 1) {
            staging_buffer.insert(staging_buffer.end(), &read_buffer[0], &read_buffer[0] + nread);
        }
        else if (nread == -1) {
            break; //Pipe is empty
        }
        else if (nread == 0) {
            break; //Error in pipe
        }
    }
    auto end_read = std::chrono::high_resolution_clock::now();
    read_time = end_read - start_read;

    if(staging_buffer.size() > 1 && staging_queue.size() < queue_limit){
        fillQueue(staging_buffer);
    }
}

//将发送的请求整合到frame_buffer中的max_payload中，替换要发送的包
int assembleData(uint8_t* frame_buffer, int dct_partition_offset, int max_payload_size) {
    int data_to_encode = 0;
    int packets_encoded = 0; //for debugging purposes
    int fragments_encoded = 0; //for debugging purposes
	//是否是调试，如果是调试则记录，默认为0
    if((staging_queue.size() > 0 || staging_queue_fragments.size() > 0) && debug) {
        logPacketsInQueue(staging_queue.size());
    }
	//data_to_encode表示当前需要编码的数据块的大小
	//max_payload_size表示每个编码数据块的最大允许大小
	//当前需要编码的数据块大小小于最大允许大小时，持续进行编码操作，直到编码出的数据块达到最大允许大小为止
    while(data_to_encode < max_payload_size){
		//存在IP数据包分段
        if(staging_queue_fragments.size() > 0){ //// If there is a fragment of an IP packet to encode
			//对IP数据包分段的头部元素的一个拷贝，创建了一个新的容器
            std::vector<uint8_t> frag(staging_queue_fragments.front());
			//frag.data()返回的是指向frag内存中第一个元素的指针
			//计算出frag中存储的IP数据包的总大小，IP数据包大小存储在头部前两个字节，高字节存储在第二个字节位置上，据此整理后得到16位无符号整数作为IP数据包的总大小
            uint16_t packet_size = ((uint16_t) frag.data()[1] << 8) | frag.data()[0];
            //如何IP数据包的片段可以被完整放入到载荷大小为max_payload_size的SRTP数据包中，那么将frag中存储的IP数据包片段的第八个字节（下标从0开始）设置为1。
			//表示IP数据包片段位整个IP数据包的最后一部分。
			//HEADER_LEN：Length of Protozoa message header
            //// The fragment fits whole
            if(data_to_encode + packet_size + HEADER_LEN <= max_payload_size){
                frag.data()[7] = 1;
                //sizeof(int)中存储了当前帧DCT分区的大小
                memcpy(&frame_buffer[dct_partition_offset + sizeof(int) + data_to_encode], &frag.data()[0], packet_size + HEADER_LEN);
                data_to_encode += packet_size + HEADER_LEN;
                staging_queue_fragments.pop_front();
                fragments_encoded += 1; //for debugging purposes
            }//// The fragment must be further fragmented but we can't even fit a header
			//空间不够，无法组装
            else if(data_to_encode + HEADER_LEN > max_payload_size){
                break;            
            }
			//可以容纳protozoa的头部，但是具体大小未知
            else{ //// The fragment will be further fragmented
                uint16_t packet_len_header = max_payload_size - data_to_encode - HEADER_LEN;
                //// Update fragment fields
                // IP_PACKET_LEN_HEADER
				//大端字节存储在数组中，便于网络传输，可以添加的数据包的长度protozoa的头
                uint8_t packet_len_header_bytes[2] = {(uint8_t) (packet_len_header >> 8), (uint8_t) (packet_len_header) };
                frag.data()[0] = packet_len_header_bytes[1];
                frag.data()[1] = packet_len_header_bytes[0];
                
                //不是最后一个分片
                //// IP_LAST_FRAG_HEADER
                frag.data()[7] = 0;
                //HEADER_LEN:protozoa_header的长度
                //// Write fragment to frame
                memcpy(&frame_buffer[dct_partition_offset + sizeof(int) + data_to_encode], &frag.data()[0], packet_len_header + HEADER_LEN);
                data_to_encode += packet_len_header + HEADER_LEN;
                
                //// Prepare resulting fragment
                std::vector<uint8_t> new_frag;
                //packet_size:frag中存储的IP数据包的总大小
                // IP_PACKET_LEN_HEADER - update new size
                uint16_t new_frag_size = packet_size - packet_len_header;
                uint8_t new_frag_size_bytes[2] = {(uint8_t) (new_frag_size >> 8), (uint8_t) (new_frag_size) };
                new_frag.push_back(new_frag_size_bytes[1]);
                new_frag.push_back(new_frag_size_bytes[0]);
                //和之前的分片保持相同的ID
                // IP_PACKET_ID_HEADER - keep id
                new_frag.push_back(frag.data()[2]);
                new_frag.push_back(frag.data()[3]);
                new_frag.push_back(frag.data()[4]);
                new_frag.push_back(frag.data()[5]);
                //将分片编号+1
                // IP_FRAG_NUM_HEADER - increase frag number
                new_frag.push_back(frag.data()[6] + 1);
                //此分片不是最后一个分片
                // IP_LAST_FRAG_HEADER - keep last frag to 0
                new_frag.push_back(0);
                //将原始数据包的有效载荷拷贝到新的分片数据包中
                //Insert data
                new_frag.insert(new_frag.end(), &frag.data()[HEADER_LEN + packet_len_header], &frag.data()[HEADER_LEN + packet_size]);
                staging_queue_fragments.push_back(new_frag);
                staging_queue_fragments.pop_front();
                break;
            }
        }
        else if(staging_queue.size() > 0){ //// If there is an IP packet to encode 有完整的IP数据包

            std::vector<uint8_t> packet(staging_queue.front());
           
            uint16_t packet_size = ((uint16_t) packet.data()[1] << 8) | packet.data()[0];
            
            if(data_to_encode + packet_size + HEADER_LEN <= max_payload_size){ // The packet fits whole
                memcpy(&frame_buffer[dct_partition_offset + sizeof(int) + data_to_encode], &packet.data()[0], packet_size + HEADER_LEN);
                data_to_encode += packet_size + HEADER_LEN;
                staging_queue.pop_front();
                packets_encoded += 1; //for debugging purposes
            }
            else if(data_to_encode + HEADER_LEN > max_payload_size){ //// The packet must be further fragmented but we can't even fit a header
                staging_queue_fragments.push_back(packet);
                staging_queue.pop_front();
                break;            
            }
            else{ //// The packet will be fragmented 数据包将被分片
                uint16_t packet_len_header = max_payload_size - data_to_encode - HEADER_LEN;
                
                //// Update fragment fields
                // IP_PACKET_LEN_HEADER
                uint8_t packet_len_header_bytes[2] = {(uint8_t) (packet_len_header >> 8), (uint8_t) (packet_len_header) };
                packet.data()[0] = packet_len_header_bytes[1];
                packet.data()[1] = packet_len_header_bytes[0];
                
                //// IP_LAST_FRAG_HEADER
                packet.data()[7] = 0;

                //// Write fragment to frame 写入帧中
                memcpy(&frame_buffer[dct_partition_offset + sizeof(int) + data_to_encode], &packet.data()[0], packet_len_header + HEADER_LEN);
                data_to_encode += packet_len_header + HEADER_LEN;
                
                //// Prepare resulting fragment
                std::vector<uint8_t> new_frag;
                
                // IP_PACKET_LEN_HEADER - update new size
                uint16_t new_frag_size = packet_size - packet_len_header;
                uint8_t new_frag_size_bytes[2] = {(uint8_t) (new_frag_size >> 8), (uint8_t) (new_frag_size) };
                new_frag.push_back(new_frag_size_bytes[1]);
                new_frag.push_back(new_frag_size_bytes[0]);
                
                // IP_PACKET_ID_HEADER - keep id
                new_frag.push_back(packet.data()[2]);
                new_frag.push_back(packet.data()[3]);
                new_frag.push_back(packet.data()[4]);
                new_frag.push_back(packet.data()[5]);
                
                // IP_FRAG_NUM_HEADER - increase frag number
                new_frag.push_back(packet.data()[6] + 1);
                
                // IP_LAST_FRAG_HEADER - keep last frag to 0
                new_frag.push_back(0);
                
                //Insert data
                new_frag.insert(new_frag.end(), &packet.data()[HEADER_LEN + packet_len_header], &packet.data()[HEADER_LEN + packet_size]);
                staging_queue_fragments.push_back(new_frag);
                staging_queue.pop_front();
                break;
            }
        } else // There is still space to encode data, but no more packets
            break;
    }

    if(packets_encoded >= 1 && debug){
        logPacketsSentInFrame(packets_encoded);
    }
    if(fragments_encoded >= 1 && debug){
        logFragmentsSentInFrame(fragments_encoded);
    }
    return data_to_encode;
}

/// <summary>
/// 将数据编码到帧缓冲区
/// </summary>
/// <param name="frame_buffer">uinit8_t类型的缓冲区</param>
/// <param name="frame_length">一个整型的帧长度</param>
/// <param name="dct_partition_offset">一个分区偏移量</param>
void encodeDataIntoFrame(uint8_t* frame_buffer, int frame_length, int dct_partition_offset) {
    
    ////Open FIFO for advertising protozoa of current payload length (P2_len - 4 bytes due to payload header -2 bytes due to terminator)
    ///打开FIFO以广播当前有效负载长度的Protozoa（P2_len-4个字节，因为有负载头-2个字节是终止符）。
	///计算第二部分DCT分区的大小	
    int dct_partition_size = frame_length - dct_partition_offset;
    int useful_dct_partition_size = dct_partition_size - sizeof(int); //// 4 bytes are used for header
    int max_payload_size = useful_dct_partition_size - 2; //// 2 bytes for packet data terminator. Client must respect it
    int data_to_encode = 0;
	//嵌入数据所需最小的字节数20:
    if(dct_partition_size >= MIN_PAYLOAD_SIZE) {

        ////Encode number of bytes in DCT partition (that the reader must read)
		///将useful_dct_partition_size复制到frame_buffer[dct_partition_offset]中，这个值表示要读取的DCT分区的字节数
        memcpy(&frame_buffer[dct_partition_offset], &useful_dct_partition_size, sizeof(int));
        ///组合数据包,在每个数据包前添加元数据，包括序列号，校验和，数据包大小信息，用于接收端还原数据，data_to_encode返回的是组合的数据包的字节。
        data_to_encode = assembleData(frame_buffer, dct_partition_offset, max_payload_size);
        //将后两个byte的值设置为0，作为终止符->2 bytes for packet data terminator. Client must respect it
        ////Encode message terminator
        memset(&frame_buffer[dct_partition_offset + sizeof(int) + data_to_encode], 0, 2);

    }
}

//从缓冲区读数据并写入解码管道中
//这里的buffer是chromium中视频载荷的内容
void retrieveDataFromFrame(uint8_t* frame_buffer, int frame_length, int dct_partition_offset) {
    int dct_partition_size = frame_length - dct_partition_offset;
    int total_written_bytes = dct_partition_offset;


    if(dct_partition_size >= MIN_PAYLOAD_SIZE) {

        ////Write decoded data
		//写入管道
        while(total_written_bytes < frame_length){
            int nwritten = write(decoder_fd, &frame_buffer[total_written_bytes], frame_length - total_written_bytes);
            if(nwritten > 0)
                total_written_bytes += nwritten;
        }
    }
}
/// <summary>
/// 打印编码图像信息，接受编码宽度、编码高度、编码长度、编码大小、是否完整帧、量化参数、帧类型、帧缓冲区和一个布尔值作为参数。
/// </summary>
/// <param name="encodedWidth">编码宽度</param>
/// <param name="encodedHeight">编码高度</param>
/// <param name="length">编码长度</param>
/// <param name="size">大小</param>
/// <param name="completeFrame">是否是完整帧</param>
/// <param name="qp">？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？</param>
/// <param name="frameType">帧的类型</param>
/// <param name="buffer">帧的缓冲区数据</param>
/// <param name="printBuffer">是否打印缓冲区数据</param>
void printEncodedImageInfo(uint32_t encodedWidth,
                           uint32_t encodedHeight,
                           size_t length,
                           size_t size,
                           bool completeFrame,
                           int qp,
                           int frameType,
                           uint8_t* buffer,
                           bool printBuffer) {

    std::cout << "[Encoded Image Structure]" << std::endl;
    std::cout << "Width: " << encodedWidth << std::endl;
    std::cout << "Height: " << encodedHeight << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Size: " << size << std::endl;
    std::cout << "Quantizer Value: " << qp << std::endl;
    std::cout << "Is complete Frame: " << completeFrame << std::endl;


    switch (frameType) {
        case 0:
            //帧类型：空帧
            std::cout << "Frame Type: EmptyFrame" << std::endl;
            break;
        case 1:
            //帧类型：语音音频帧
            std::cout << "Frame Type: AudioFrameSpeech" << std::endl;
            break;
        case 2:
            //帧类型：CN（Comfort Noise）音频帧
            //Comfort Noise（CN），也称为安慰噪声，是一种在无声区间中用于补充缺失的声音的技术。
            //在语音通信中，当一个人说话时，会在声音信号中产生一些静音的时间段。当另一个人听到这段时间时，会感到非常不自然。
            //为了避免这种情况，通过在静音区间中插入与说话人声音类似的安慰噪声，来保持连续的声音信号
            std::cout << "Frame Type: AudioFrameCN" << std::endl;
            break;
        case 3:
            //帧类型：关键帧
            std::cout << "Frame Type: VideoFrameKey" << std::endl;
            break;
        case 4:
            //帧类型：Delta帧（参考帧）。
            //在视频编码中，参考帧是用于压缩后续帧数据的基准帧。
            //通常，视频压缩算法将关键帧和参考帧进行编码，其中关键帧是编码视频序列的独立图像，而参考帧则只包含像素之间的差异或变化。
            //在解码视频时，解码器使用参考帧来重建压缩的视频帧。使用参考帧可以极大地减少视频数据的存储空间和传输带宽
            std::cout << "Frame Type: VideoFrameDelta" << std::endl;
            break;
    }

    if(printBuffer){
        for (unsigned long i = 0; i < length; i++)
            printf("0x%02x ", buffer[i]);
        printf("\n");
    }
    std::cout << std::endl;
}



