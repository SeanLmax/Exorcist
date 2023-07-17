/*
 * @Date: 2023-07-12 13:53:11
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-07-12 16:33:45
 * @FilePath: /pebs/src/pebs_taine.c
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>

#include "pebs_taine.h"


/**
 * 污点分析
*/
void pebs_taine_analyze(struct task_struct * task, uint64_t start_addr, uint64_t end_addr){

    // 获取指定进程的内存描述符
    struct mm_struct *mm = task->mm;
    unsigned long code_size = (end_addr - start_addr);
    printk(KERN_INFO "code info, start_addr:%lx,end_addr:%llx,size:%d\n", start_addr, end_addr,code_size);

    // 计算需要映射的页数
    unsigned long nr_pages = (start_addr + code_size - 1) / PAGE_SIZE - start_addr / PAGE_SIZE + 1;
    printk(KERN_ERR "nr_pages:%d\n",nr_pages);

    // 分配页框指针数组,kvmalloc分配的是可重用的虚拟内存区域
    struct page **pages = kvmalloc(nr_pages * PAGE_SIZE, GFP_KERNEL);

    // 用于返回锁定标志。如果为1，表示返回的页框已经被锁定
    int* locked;

    // 映射用户空间的地址到内核空间中
    int ret = get_user_pages_remote(mm, start_addr, nr_pages, FOLL_WRITE | FOLL_FORCE, pages, NULL, locked);
    if (ret <= 0) {
        printk(KERN_ERR "Failed to get user pages\n");
        kvfree(pages);
        return;
    }

    // 分配指定的内存区域，并清零
    char *data = kvzalloc(code_size, GFP_KERNEL);
    if (data == NULL) {
        printk(KERN_ERR "Failed to allocate memory.....\n");
        int i=0;
        for (; i < nr_pages; i++) {
            put_page(pages[i]);
        }
        kvfree(pages);
        return;
    }

    int i=0;
    for(;i<code_size;i++){
        long long int val = *(data + i);
        printk(KERN_INFO "data initial val, address:%llx,val:%llx\n", (data+i), val);
    }

    i = 0;
    unsigned long copied = 0;
    unsigned long remain = code_size;
    // 将分散的页框数据映射到连续的内核空间中
    for (; i < nr_pages; i++) {

        // 根据用户地址计算页内偏移量，因为用户空间所有的数据都是从头开始编址的，因此直接模page_size即可
        unsigned long offset = start_addr % PAGE_SIZE;
        printk(KERN_INFO "i=%d. offset=%d.\n", i, offset);
        
        unsigned long len = min((unsigned long)PAGE_SIZE - offset, remain);
        printk(KERN_INFO "i=%d. len=%d.\n", i, len);

        // 用于将一个页框映射到内核空间中，并返回映射后的虚拟地址
        void *src = kmap(pages[i]) + offset;
        void *dst = data + copied;
        printk(KERN_INFO "src=%llx;dst=%llx;\n", (unsigned long long int *)src, (unsigned long long int *)dst);

        memcpy(dst, src, len);
        kunmap(pages[i]);
        copied += len;
        remain -= len;
        
    }
    printk(KERN_INFO "i=%d.\n", i);

    i=0;
    for(;i<code_size;i++){
        long long int val = *(data + i);
        printk(KERN_INFO "Read data from user space, address:%llx,val:%llx\n", (data+i), val);
    }

    // 释放页框和内存
    i = 0;
    for (; i < nr_pages; i++) {
        put_page(pages[i]);
    }
    kvfree(pages);
    kvfree(data);

    return;
}