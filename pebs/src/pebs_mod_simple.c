/*
*   Description :   PEBS内核模块开发
*   Date:   2023/05/11
*   Author: chang.liu
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/current.h>
#include <linux/netlink.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "pebs_mod.h"
#include "pebs_pub.h"
#include "pebs_buffer.h"
#include "pebs_taine.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TEE Team");
MODULE_DESCRIPTION("Hook and anaysis pebs data");
MODULE_VERSION("1.0");

static char *enable = "Y";
module_param(enable, charp, S_IRUGO);
MODULE_PARM_DESC(enable, "Pebs hook switch");
EXPORT_SYMBOL_GPL(pebs_record_handler); 

// 配置PEBS能力启用的寄存器地址
#define MSR_PEBS_ENABLE 0x3f1

// 配置关注事件类型的寄存器地址
#define MSR_PERFEVTSEL0 0x186
#define MSR_PERFEVTSEL1 0x187

// 通用计数器地址
#define MSR_GP_COUNT_PMC0 0xc1
#define MSR_GP_COUNT_PMC1 0xc2

// 固定计数器地址
#define MSR_FIXED_CTR0 0x309
#define MSR_FIXED_CTR1 0x30A
#define MSR_FIXED_CTR2 0x30B
#define MSR_FIXED_CTR3 0x30C

// 控制固定计数器是否启用的寄存器地址
#define MSR_FIXED_CTR_CTRL 0x38D

// cache miss的事件类型编码\掩码
#define CACHE_MISS_EVENT_TYPE 0xD1
#define CACHE_MISS_UMASK 0x08

//cache miss事件 PEBS事件记录内存地址最后两位的值\事件类型
#define CACHE_MISS_MEM_ADDR_LOW_2_BIT_VAL 0x01d5
#define CACHE_MISS_EVENT_ENUM 1

// branch miss的事件类型编码\掩码
#define BRANCH_MISS_EVENT_TYPE 0xC5
#define BRANCH_MISS_UMASK 0x20
//#define BRANCH_MISS_UMASK 0x04

// branch miss的事件 PEBS事件记录内存地址最后两位的值\事件类型
#define BRANCH_MISS_MEM_ADDR_LOW_2_BIT_VAL 0x01e1
#define BRANCH_MISS_EVENT_ENUM 2

// 批量设置&查询计数器（通用 or 固定）状态
#define MSR_PERF_GLOBAL_STATUS 0x38E
#define MSR_PERF_GLOBAL_CTRL 0x38F
#define MSR_PERF_GLOBAL_OVF_CTRL 0x390

// 存放ds缓存区首地址的寄存器地址
#define MSR_DS_AREA 0x600

// 配置PEBS每条Record记录的格式的寄存器地址
#define MSR_PEBS_DATA_CFG 0x3F2

// 配置PEBS Record记录位数的寄存器地址
#define MSR_PERF_CAPABILITIES 0x345

// 整个PEBS Record Buffer区域的最大值:4M，单位为字节
#define PEBS_BUFFER_SIZE_BYTE 4 * 1024 * 1024

// 计数器的reset值，也是一个计数周期的值。每个周期完成后，会记录一条PEBS 记录。
#define PERIOD 1

// 线程休眠的毫秒数
#define THREAD_SLEEP_MILL_SECONDS 1

// DS结构体
typedef struct pebs_debug_store {
	uint64_t bts_base;
	uint64_t bts_index;
	uint64_t bts_max;
	uint64_t bts_thresh;

	uint64_t pebs_base;
	uint64_t pebs_index;
	uint64_t pebs_max;
	uint64_t pebs_thresh;
	int64_t pebs_counter_reset[4];

    uint64_t reserved;
} debug_store_t;

// 引入外部定义钩子
extern void (*pebs_handler)(void);

// pebs记录的大小---64个字节按照basic_info + mem_info计算
static uint32_t pebs_record_size = 64;

// 定义CPU本地变量，指向ds struct区域的指针
static DEFINE_PER_CPU(debug_store_t *, cpu_ds_p);

static DEFINE_PER_CPU(uint64_t, cpu_old_ds);

// 线程
static struct task_struct* pthread;

// 缓存区记录总数
static atomic_t total = ATOMIC_INIT(0);

static bool check(void){
    uint64_t val;

    //1. 校验是否有其他程序使用PMU
    rdmsrl(MSR_PERFEVTSEL0, val);
	if ((val >> 22) & 0x1 == 1) {
		printk(KERN_INFO "cpu-%d:Someone else using perf counter 0\n",get_cpu());
		return false;
	}

    val = (uint64_t)0;
    rdmsrl(MSR_PERFEVTSEL1, val);
	if ((val >> 22) & 0x1 == 1) {
		printk(KERN_INFO "cpu-%d:Someone else using perf counter 1\n",get_cpu());
		return false;
	}

    //2. 根据寄存器配置确定PEBS记录的格式以及大小
    uint64_t cap;
    rdmsrl(MSR_PERF_CAPABILITIES, cap);
    printk(KERN_INFO "cpu-%d:MSR_PERF_CAPABILITIES value=%llx\n",get_cpu(),cap);

    /*
    char* record_version;

    switch ((cap >> 8) & 0xf) {
    case 1:
        pebs_record_size = sizeof(pebs_v1_t);
        record_version = "pebs_v1_t";
        break;
    case 2:
        pebs_record_size = sizeof(pebs_v2_t);
        record_version = "pebs_v2_t";
        break;
    case 3:
        pebs_record_size = sizeof(pebs_v3_t);
        record_version = "pebs_v3_t";
        break;
    default:
        printk(KERN_ERR "cpu-%d:Unsupported PEBS format\n",get_cpu());
        return false;
    }

    printk(KERN_INFO "cpu-%d:pebs record version:%s\n",get_cpu() , record_version);
    */

    return true;
}

static uint64_t cal_branch_miss_ctrl_val(void){
    uint64_t ctrl_val = 0x00;

    // 设置事件类型
    ctrl_val |= (0x000000FF & BRANCH_MISS_EVENT_TYPE);

    // 设置事件掩码
    ctrl_val |= (0x0000FF00 & (BRANCH_MISS_UMASK << 8));

    // 设置开启用户态监控模式
    ctrl_val |= (1 << 16);

    //开启内核态监控
    //ctrl_val |= (1 << 17);

    // 设置监控边缘触发事件
    ctrl_val |= (1 << 18);

    // 设置Pin Control：如果设置为1，当性能监控事件发生时，计数器就会增加一个计数，并toggles the PMi pins。如果设置为0，则只有当计数溢出时，才会toggles the PMi pins。
    //ctrl_val |= (0 << 19);

    // 设置APIC中断使能开关开启。如果为1则计数器溢出时，会通过local APIC触发CPU产生一个异常。
    // 是否需要关闭？？？
    //ctrl_val |= (1 << 20);

    // ANY Thread
    //ctrl_val |= (1 << 21);

    // 设置性能计数器为生效状态
    ctrl_val |= (1 << 22);

    // 设置不对Counter mask结果进行反转
    //ctrl_val |= (0 << 23);

    // 设置CMASK字段24~31位
    // 如果字段不为0，则只有在单个时钟周期内发生的事件数大于等于该值，对应的计数器才会自增1；否则就是每个事件都记录，也就是全样本采集。
    //ctrl_val |= (0xFF000000 & 0x0);

    // ADEPTIVE record
    ctrl_val |= (((uint64_t)1) << 34);



    return ctrl_val;
}

static uint64_t cal_cache_miss_ctrl_val(void){
    uint64_t ctrl_val = 0x00;

    // 设置事件类型
    ctrl_val |= (0x000000FF & CACHE_MISS_EVENT_TYPE);

    // 设置事件掩码
    ctrl_val |= (0x0000FF00 & (CACHE_MISS_UMASK << 8));

    // 设置开启用户态监控模式
    ctrl_val |= (1 << 16);

    // 开启内核态监控
    //ctrl_val |= (1 << 17);

    // 设置监控边缘触发事件
    ctrl_val |= (1 << 18);

    // 设置Pin Control
    //ctrl_val |= (0 << 19);

    // 设置APIC中断使能开关关闭
    //ctrl_val |= (1 << 20);

    // 设置性能计数器为生效状态
    ctrl_val |= (1 << 22);

    // 设置不对Counter mask结果进行反转
    //ctrl_val |= (0 << 23);

    // 设置CMASK字段24~31位
    //ctrl_val |= (0xFF000000 & 0x0);

    // ADEPTIVE record
    ctrl_val |= (((uint64_t)1) << 34);

    return ctrl_val;
}


static void print_ds_info(void){
    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p != NULL){
        printk(KERN_INFO "cpu-%d:debug_store info: pebs_base=%llx,pebs_index=%llx,pebs_max=%llx,pebs_thresh=%llx,pebs_counter_0=%llx,pebs_counter_1=%llx\n", 
                get_cpu(),
                ds_p->pebs_base,
                ds_p->pebs_index,
                ds_p->pebs_max,
                ds_p->pebs_thresh,
                ds_p->pebs_counter_reset[0],
                ds_p->pebs_counter_reset[1]);
    }else{
        printk(KERN_ERR "cpu-%d:ds_p is NULL.\n", get_cpu());
    }
}

static void print_msr_info(void){
    printk(KERN_INFO "cpu-%d:---------------msr info-------------\n",get_cpu());
    uint64_t val;

    rdmsrl(MSR_PERFEVTSEL0,val);
    printk(KERN_INFO "cpu-%d:MSR_PERFEVTSEL0(%llx)=%llx\n",get_cpu(),MSR_PERFEVTSEL0,val);

    rdmsrl(MSR_PERFEVTSEL1,val);
    printk(KERN_INFO "cpu-%d:MSR_PERFEVTSEL1(%llx)=%llx\n",get_cpu(),MSR_PERFEVTSEL1,val);

    rdmsrl(MSR_PEBS_ENABLE,val);
    printk(KERN_INFO "cpu-%d:MSR_PEBS_ENABLE(%llx)=%llx\n",get_cpu(),MSR_PEBS_ENABLE,val);

    rdmsrl(MSR_GP_COUNT_PMC0,val);
    printk(KERN_INFO "cpu-%d:MSR_GP_COUNT_PMC0(%llx)=%llx\n",get_cpu(),MSR_GP_COUNT_PMC0,val);

    rdmsrl(MSR_GP_COUNT_PMC1,val);
    printk(KERN_INFO "cpu-%d:MSR_GP_COUNT_PMC1(%llx)=%llx\n",get_cpu(),MSR_GP_COUNT_PMC1,val);

    rdmsrl(MSR_DS_AREA,val);
    printk(KERN_INFO "cpu-%d:MSR_DS_AREA(%llx)=%llx\n",get_cpu(),MSR_DS_AREA,val);

    rdmsrl(MSR_PERF_CAPABILITIES,val);
    printk(KERN_INFO "cpu-%d:MSR_PERF_CAPABILITIES(%llx)=%llx\n",get_cpu(),MSR_PERF_CAPABILITIES,val);

    rdmsrl(MSR_PEBS_DATA_CFG,val);
    printk(KERN_INFO "cpu-%d:MSR_PEBS_DATA_CFG(%llx)=%llx\n",get_cpu(),MSR_PEBS_DATA_CFG,val);

    printk(KERN_INFO "cpu-%d:---------------msr info-------------\n",get_cpu());
}

static bool set_ds_buffer(void){
    // 申请DS结构体内存,GFP_KERNEL表示内核内存空间分配模式
    debug_store_t* ds_p = kmalloc(sizeof(debug_store_t), GFP_KERNEL);
    if(ds_p != NULL){
        printk(KERN_INFO "cpu-%d:debug_store kmalloc success. address=%llx\n",get_cpu(),ds_p);
    }else{
        printk(KERN_ERR "cpu-%d:debug_store kmalloc failed.",get_cpu());
        return false;
    }
    memset(ds_p, 0, sizeof(debug_store_t));

    // 申请PEBS record buffer区域内存
    ds_p->pebs_base = (uint64_t)kmalloc(PEBS_BUFFER_SIZE_BYTE, GFP_KERNEL);
    if(ds_p->pebs_base != NULL){
        printk(KERN_INFO "cpu-%d:pebs buffer kmalloc success. address=%llx\n",get_cpu(),ds_p->pebs_base);
    }else{
        printk(KERN_ERR "cpu-%d:pebs buffer kmalloc failed.",get_cpu());
        return false;
    }
    memset((void *)ds_p->pebs_base,0,PEBS_BUFFER_SIZE_BYTE);
    
    // 设置DS的其他值
    uint64_t pebs_max_num = PEBS_BUFFER_SIZE_BYTE / pebs_record_size;
    ds_p->pebs_index = ds_p->pebs_base;
    ds_p->pebs_max = ds_p->pebs_base + (pebs_max_num -1)*pebs_record_size;

    // 触发PEBS Buffer 中断的阀值
    //ds_p->pebs_thresh = ds_p->pebs_base + (pebs_max_num - pebs_max_num/10) * pebs_record_size ;
    ds_p->pebs_thresh = ds_p->pebs_max;

    ds_p->pebs_counter_reset[0] = -(int64_t)PERIOD;
    ds_p->pebs_counter_reset[1] = -(int64_t)PERIOD;


    // 写入到本地CPU变量中
    __this_cpu_write(cpu_ds_p, ds_p);

    print_ds_info();

    return true;
}

void pebs_pmi_handler(void){

}

static void pebs_mod_init_each_cpu(void *arg){
    printk(KERN_INFO "cpu-%d:*************PEBS module load start!*************\n", get_cpu());

    // 校验 并做一些计算全局变量操作
    if(check()==false){
        return;
    }

    // 申请和设置DS buffer区域相关信息
    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p == NULL){
        if(set_ds_buffer() == false){
            return;
        }
    }

    //将Buffer首地址设置到IA32_DS_AREA寄存器中。
    uint64_t old_ds;
    rdmsrl(MSR_DS_AREA, old_ds);
    //将旧值暂存
	__this_cpu_write(cpu_old_ds, old_ds);
    wrmsrl(MSR_DS_AREA, (uint64_t)__this_cpu_read(cpu_ds_p));

    //设置PEBS record关注的信息
    // 只关注basic和memory，basic_info默认开启，memory_info控制位为最低位
    wrmsrl(MSR_PEBS_DATA_CFG,(uint64_t)1);

    // 先禁用PMU功能（对应MSR_PERFEVTSEL0&1的计数器Enable字段设置为0）
    wrmsrl(MSR_PERF_GLOBAL_CTRL, 0);

    // 设置关注的事件类型
    uint64_t cache_miss_val = cal_cache_miss_ctrl_val();
    printk(KERN_INFO "cpu-%d:cache_miss MSR_PERFEVTSEL0 val=%llx\n",get_cpu(), cache_miss_val);
    wrmsrl(MSR_PERFEVTSEL0,cache_miss_val);
    
    uint64_t branch_miss_val = cal_branch_miss_ctrl_val();
    printk(KERN_INFO "cpu-%d:branch_miss MSR_PERFEVTSEL1 val=%llx\n",get_cpu(), branch_miss_val);
    wrmsrl(MSR_PERFEVTSEL1,branch_miss_val);

    // 设置PMC0、PMC1计数器的初始值
    wrmsrl(MSR_GP_COUNT_PMC0, -(int64_t)PERIOD);
    wrmsrl(MSR_GP_COUNT_PMC1, -(int64_t)PERIOD);

    // 启用PEBS功能（开启PMC0&PMC1的PEBS能力）
    wrmsrl(MSR_PEBS_ENABLE, 0x03);

    // 启用PMU功能（对应MSR_PERFEVTSEL0&1的计数器Enable字段设置为1）
    wrmsrl(MSR_PERF_GLOBAL_CTRL, 0x03);

    print_msr_info();

    printk(KERN_INFO "cpu-%d:*************PEBS module load success!*************\n",get_cpu());
}

static int thread_func(void *arg)
{
    printk(KERN_INFO "cpu-%d:kthread start.\n",get_cpu());

    while(!kthread_should_stop()){
        uint32_t count = 0;
        short sleep_count = 0;

        // 读取内存区域，并执行进程的kill操作
        uint32_t num = num_online_cpus();
        uint32_t index = 0;
        for(; index < num; index ++){
            uint32_t pid;
            uint64_t start_addr;
            uint64_t end_addr;
            while(read_ring_buffer(index, &pid, &start_addr, &end_addr) == 0){
                
                struct pid * kpid = find_vpid((int32_t)pid);
                struct task_struct * task = pid_task(kpid, PIDTYPE_PID);
                // 判断进程是否活跃，如果是活跃的就进入下一步污点分析
                if(pid_alive(task) == 1){
                    printk(KERN_INFO "cpu-%d: suspicious pid=%d, start_addr=%llx, end_addr=%llx.\n", get_cpu(), pid, start_addr, end_addr);
                    
                    // 污点分析
                    pebs_taine_analyze(task,start_addr,end_addr);

                    count ++;
                    if(sleep_count > 0){
                        sleep_count = 0;
                    }
                }
                
            }
        }

        if(count == 0){
            if(sleep_count < 10){
                sleep_count ++;
            }

            // 休眠，让出CPU
            msleep(THREAD_SLEEP_MILL_SECONDS * sleep_count);
        }
    }

    printk(KERN_INFO "cpu-%d:kthread stop.\n",get_cpu());
    
    return 0;
}

static int __init pebs_mod_init(void)
{
    // 对每一个CPU进行初始化设置
    on_each_cpu(pebs_mod_init_each_cpu,NULL,1);

    // 申请一片公共的内存区域
    alloc_ring_buffer();

    // 创建一个内核线程
    pthread = kthread_run(thread_func, NULL, "pebs_thread");
    if (IS_ERR(pthread)) {  
        printk(KERN_ERR "create pebs_thread failed!\n");
    }

    // 设置内核钩子处理函数
    pebs_handler = pebs_record_handler;
    
    return 0;
}

static void print_pebs_buffer_records(void){

    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p != NULL){

        uint64_t cur_addr = ds_p->pebs_base;
        uint64_t end_addr = ds_p->pebs_index;
        printk(KERN_INFO "cpu-%d:PEBS record info: start_addr=%llx, end_addr=%llx\n",get_cpu(),cur_addr,end_addr);

        uint64_t* cur_p = cur_addr;
        //basic_info 和 mem_info各占32个字节，因此一条记录是64个字节
        uint64_t total_rec_count = (end_addr - cur_addr)/pebs_record_size;
        printk(KERN_INFO "cpu-%d:pebs buffer record count:%lld\n",get_cpu(),total_rec_count);
        
        uint64_t i = 0;
        uint64_t count = total_rec_count * 8;
        while(i < count){
            uint64_t val = *(cur_p+i);
            if((val & 0xff) == 0xd5 || (val & 0xff) == 0xe1){
                // 输出record的值（按照8字节一条数据的方式）
                printk(KERN_INFO "cpu-%d:address:%llx,PEBS record value:%llx(target)\n",get_cpu(),(cur_p+i),*(cur_p+i)); 
            }else{
               printk(KERN_INFO "cpu-%d:address:%llx,PEBS record value:%llx\n",get_cpu(),(cur_p+i),*(cur_p+i)); 
            }
            
            i++;
        }
    }
}

static void pebs_reset(void){
    wrmsrl(MSR_PERF_GLOBAL_CTRL, (uint64_t)0);
	wrmsrl(MSR_PEBS_ENABLE, (uint64_t)0);
	wrmsrl(MSR_PERFEVTSEL0, (uint64_t)0);
    wrmsrl(MSR_PERFEVTSEL1, (uint64_t)0);
	wrmsrl(MSR_GP_COUNT_PMC0, (uint64_t)0);
    wrmsrl(MSR_GP_COUNT_PMC1, (uint64_t)0);
    wrmsrl(MSR_PEBS_DATA_CFG, (uint64_t)0);
    wrmsrl(MSR_DS_AREA, __this_cpu_read(cpu_old_ds));

    print_msr_info();
    
}

static void pebs_mod_exit_each_cpu(void *arg){

    printk(KERN_INFO "cpu-%d:***********PEBS module exit start!*********\n",get_cpu());

    uint64_t val_addr;
    rdmsrl(MSR_DS_AREA,val_addr);
    printk(KERN_INFO "cpu-%d:rmmod: read value from MSR_DS_AREA, address=%llx\n",get_cpu(),val_addr);
    
    // 打印输出缓冲区的PEBS记录
    //print_pebs_buffer_records();

    // 重置各种MSR值
    pebs_reset();

    // 释放为DS申请的内核内存空间
    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p != NULL){
       if(ds_p->pebs_base != NULL){
            kfree((void *)ds_p->pebs_base);
       }
       kfree(ds_p);
       printk(KERN_INFO "cpu-%d:ds buffer free success!\n",get_cpu());
    }

    printk(KERN_INFO "cpu-%d:**********PEBS module exit success!********\n",get_cpu());

}


static void __exit pebs_mod_exit(void)
{
    printk(KERN_INFO "cpu-%d: system has %d processor(s).\n", get_cpu(), num_online_cpus());

    pebs_handler = NULL;
    
    // 在所有CPU核心上按照核心顺序执行退出逻辑
    int i = 0;
    int num = num_online_cpus();
    for (; i < num; i++){
        smp_call_function_single(i, pebs_mod_exit_each_cpu, NULL, 1);
    }
    
    // 停止线程
    kthread_stop(pthread);

    // 释放环形缓冲区
    free_ring_buffer();

}

static void print_pebs_record_single(uint64_t *address_p){
    unsigned short count = 4;
    unsigned short i = 0;
    for(; i<count; i++){
        printk(KERN_INFO "cpu-%d:address:%llx,pebs valid record value:%llx\n",get_cpu(),(address_p+i),*(address_p+i));
    }
}

/**
 * 读取buffer中的记录，定位查找符合要求的pair
 * 记录1：
 * offset:0x08 val（内存地址）: 最后两位十六进制数字是e1
 * offset:0x10 val（计数器事件类型）: 2
 * offset:0x18 val（时间戳）: 
 * 
 * 记录2：
 * offset:0x08 val（内存地址）：最后两位十六进制数字是d5
 * offset:0x10 val（计数器事件类型）：1
 * offset:0x18 val（时间戳）: 
 * 
 * 满足如下要求：
 * 1）内存地址间隔在16个字节以内
 * 2）时间戳间隔在300个cycle以内
 * 
 * 
*/
void pebs_record_handler(void)
{  
    // 获取当前CPU进程信息
    struct task_struct* current_pid = current;
    //printk(KERN_INFO "cpu-%d:current pid=%d\n",get_cpu(),current_pid->pid);

    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);

    uint64_t start_addr = ds_p->pebs_base;

    uint64_t* cur_p_2 = ds_p->pebs_index - pebs_record_size; //branch_miss事件记录指针
    uint64_t* cur_p_1 =  ds_p->pebs_index - 2 * pebs_record_size;//cache_miss事件记录指针

    while(cur_p_2 > start_addr && cur_p_1>=start_addr){
        uint64_t mem_addr_2 = *(cur_p_2 + 1);
        uint64_t count_type_2 = *(cur_p_2 + 2);
        uint64_t tsp_2 = *(cur_p_2 + 3);

        // 找branch_miss事件且内存地址最后两位为指定的值
        if(count_type_2 != BRANCH_MISS_EVENT_ENUM || 
            (mem_addr_2 & 0x0fff) != BRANCH_MISS_MEM_ADDR_LOW_2_BIT_VAL){
            cur_p_2 = cur_p_2 - pebs_record_size/8;
            continue;
        }

        // 只往回找
        if(cur_p_1 >= cur_p_2){
            cur_p_1 = cur_p_2 - pebs_record_size/8;
        }
        
        while(cur_p_1>=start_addr){
            uint64_t mem_addr_1 = *(cur_p_1 + 1);
            uint64_t count_type_1 = *(cur_p_1 + 2);
            uint64_t tsp_1 = *(cur_p_1 + 3);

            // 找cache_miss事件且内存地址最后两位为指定的值
            if(count_type_1 != CACHE_MISS_EVENT_ENUM || 
                (mem_addr_1 & 0x0fff) != CACHE_MISS_MEM_ADDR_LOW_2_BIT_VAL){
                cur_p_1 = cur_p_1 - pebs_record_size/8;
                continue;
            }

            printk(KERN_INFO "cpu-%d: judge tsp.\n",get_cpu());
            
            // 比较地址差值是否在16个字节内
            uint64_t mem_addr_sub = mem_addr_2 > mem_addr_1 ? (mem_addr_2-mem_addr_1) : (mem_addr_1-mem_addr_2);
            if(mem_addr_sub > 16){
                cur_p_1 = cur_p_1 - pebs_record_size/8;
                continue;
            }

            //判断时间戳是否在300个cycle内，如果不在直接结束内层循环。
            if((tsp_2-tsp_1) > 300){
                goto fail_tag;
            }

            print_pebs_record_single(cur_p_1);
            print_pebs_record_single(cur_p_2);

            // 将pid写入到共享内存中
            write_ring_buffer(current_pid->pid, *(cur_p_1+1), *(cur_p_2+1));
            printk(KERN_INFO "cpu-%d: write into buffer.pid=%d;start_addr=%llx;end_addr=%llx.\n",
                    get_cpu(), current_pid->pid, *(cur_p_1+1), *(cur_p_2+1));

            goto out_tag;
        }

        fail_tag:
            //cur_p_2 = cur_p_1 - pebs_record_size/8;
            cur_p_2 = cur_p_1;
            cur_p_1 = cur_p_2 - pebs_record_size/8;
    }
    
    out_tag:
    // 重置index以及计数器的值
    ds_p->pebs_index = ds_p->pebs_base;
    ds_p->pebs_counter_reset[0] = -(int64_t)PERIOD;
    ds_p->pebs_counter_reset[1] = -(int64_t)PERIOD;

}

module_init(pebs_mod_init);
module_exit(pebs_mod_exit);