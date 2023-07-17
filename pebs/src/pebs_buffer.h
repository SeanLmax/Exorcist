/*
 * @Date: 2023-06-08 11:16:04
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-07-12 15:23:08
 * @FilePath: /pebs/src/pebs_buffer.h
 */
#ifndef PEBS_BUFFER_H
#define PEBS_BUFFER_H

#include "pebs_pub.h"

void alloc_ring_buffer(void);

void free_ring_buffer(void);

void write_ring_buffer(uint32_t pid, uint64_t start_addr, uint64_t end_addr);

int8_t read_ring_buffer(uint32_t ring_buffer_id, uint32_t* pid, uint64_t* start_addr, uint64_t* end_addr);

#endif