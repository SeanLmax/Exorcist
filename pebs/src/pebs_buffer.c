/*
 * @Date: 2023-06-08 09:20:16
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-07-12 17:46:18
 * @FilePath: /pebs/src/pebs_buffer.c
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include "pebs_pub.h"
#include "pebs_buffer.h"

// 一个pid的字节数（64位的long long int），start_addr & end_addr的字节数（64位的long long int）1024-pid的个数（2的指数）
#define RING_BUFFER_ITEM_SINGLE_SIZE_BYTES 24

// 一个环形缓存区ITEM的字节数，一个环的大小为1024个
#define RING_BUFFER_ITEM_TOTAL_SIZE_BYTES RING_BUFFER_ITEM_SINGLE_SIZE_BYTES*1024


typedef struct buffer_item{
    // item的内存基址
    uint64_t* buffer_item_base;

    // 读指针index，指向最近一次读取的位置
    int64_t read_index;

    // 写指针index，指向可写入的位置
    int64_t write_index;

}buffer_item_t;

typedef struct ring_buffers{
    // buffer的内存基址指针
    uint32_t* buffer_base;

    // ring_buffer的个数
    uint32_t item_size;

    // 结构体数组（最多支持100个核）
    buffer_item_t items[100];
}ring_buffers_t;

ring_buffers_t buffers;


/**
 * 分配ring buffer空间
*/
void alloc_ring_buffer(void){
    buffers.buffer_base = NULL;
    
    // 可用的cpu核数
    uint32_t num = num_online_cpus();
    if(num > 100){
        printk(KERN_ERR "ring buffer max size is 100....");
        return;
    }

    // 分配连续的内存空间，对于一个24核的系统，分配的内存大小为576kb
    buffers.buffer_base = (uint32_t*)kmalloc(num * RING_BUFFER_ITEM_TOTAL_SIZE_BYTES, GFP_KERNEL);
    buffers.item_size = num;
    
    short index = 0;
    for(; index<num; index++){
        buffers.items[index].read_index = -1;
        buffers.items[index].write_index = 0;
        // 因为buffers.buffer_base 指针是32为int，所以在执行加法时，需要除以字节数（4）
        buffers.items[index].buffer_item_base = (uint64_t*)(buffers.buffer_base + (index * RING_BUFFER_ITEM_TOTAL_SIZE_BYTES/4));
    }

    /*
    printk(KERN_INFO "ring buffer info: buffer_base=%llx;item_size=%d;item_arr_size=%d\n", buffers.buffer_base, buffers.item_size, sizeof(buffers.items));
    index = 0;
    for(; index<num; index++){
        buffer_item_t item = buffers.items[index];
        printk(KERN_INFO "ring buffer arr info: index=%d;buffer_item_base=%llx;read_index=%d;write_index=%d\n", index, item.buffer_item_base, item.read_index, item.write_index);
    }
    */
}

/**
 * 释放buffer ring空间
*/
void free_ring_buffer(void){
    buffers.item_size = 0;
    
    if(buffers.buffer_base != NULL){
        // 释放内存
        kfree((void *)buffers.buffer_base);
    }

    // 重置数据
    short index = 0;
    for(;index < 100; index++){
        buffer_item_t item = buffers.items[index];
        item.read_index = 0;
        item.write_index = 0;
        item.buffer_item_base = NULL;
    }

}

/**
 * 将pid写入到内存区域中
*/
void write_ring_buffer(uint32_t pid, uint64_t start_addr, uint64_t end_addr){
    int cpu_id = get_cpu();
    buffer_item_t item = buffers.items[cpu_id];

    // 写入值
    uint64_t* cur_p = item.buffer_item_base + item.write_index * RING_BUFFER_ITEM_SINGLE_SIZE_BYTES;
    *(cur_p) = ((uint64_t)pid);
    *(cur_p+1) = start_addr;
    *(cur_p+2) = end_addr;

    printk(KERN_INFO "buffer_id_%d:write into buffer, pid=%d, start_addr=%llx, end_addr=%llx.\n", cpu_id, *(cur_p), *(cur_p+1), *(cur_p+2));

    buffers.items[cpu_id].write_index =(item.write_index+1) & (RING_BUFFER_ITEM_TOTAL_SIZE_BYTES/RING_BUFFER_ITEM_SINGLE_SIZE_BYTES - 1);
}

/**
 * 读取指定ring_buffer_id的一个元素，如果无元素可读，则返回-1
*/
int8_t read_ring_buffer(uint32_t ring_buffer_id, uint32_t* pid, uint64_t* start_addr, uint64_t* end_addr){
    
    if(ring_buffer_id > (buffers.item_size-1)){
        return -1;
    }

    buffer_item_t item = buffers.items[ring_buffer_id];
    // 无元素可读
    if(item.read_index == (item.write_index-1)){
        return -1;
    }

    item.read_index = (item.read_index+1) & (RING_BUFFER_ITEM_TOTAL_SIZE_BYTES/24-1);
    uint64_t* cur_p = item.buffer_item_base + item.read_index * RING_BUFFER_ITEM_SINGLE_SIZE_BYTES;
    *(pid) = (uint32_t)(*(cur_p));
    *(start_addr) = *(cur_p+1);
    *(end_addr) = *(cur_p+2);

    buffers.items[ring_buffer_id].read_index = item.read_index;

    return 0;
}