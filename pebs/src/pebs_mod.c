/*
*   Description :   PEBS内核模块开发
*   Date:   2023/05/11
*   Author: chang.liu
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/netlink.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <linux/kallsyms.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include "pebs_mod.h"
#include "pebs_pub.h"

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

#define LOG_FILE_NAME_PREFFIX "/home/tee/liuchang/log/pebs"
#define LOG_FILE_NAME_SUFFIX ".log"

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

// buffer记录统计数据
static DEFINE_PER_CPU(uint64_t, cpu_buffer_count);
static DEFINE_PER_CPU(uint64_t, cpu_buffer_cycle_count);
static DEFINE_PER_CPU(uint64_t, cpu_buffer_max_count);
static DEFINE_PER_CPU(uint64_t, cpu_buffer_min_count);

// valid buffer记录统计数据
static DEFINE_PER_CPU(uint64_t, cpu_total_count);
static DEFINE_PER_CPU(uint64_t, cpu_cycle_count);
static DEFINE_PER_CPU(uint64_t, cpu_max_count);
static DEFINE_PER_CPU(uint64_t, cpu_min_count);

static DEFINE_PER_CPU(uint64_t, cpu_total_cost_time);
static DEFINE_PER_CPU(uint64_t, cpu_min_cost_time);
static DEFINE_PER_CPU(uint64_t, cpu_max_cost_time);


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

static void init_buffer_stat(void){

    __this_cpu_write(cpu_buffer_count,0);
    __this_cpu_write(cpu_buffer_cycle_count,0);
    __this_cpu_write(cpu_buffer_max_count,0);
    __this_cpu_write(cpu_buffer_min_count,0);

    __this_cpu_write(cpu_total_count,0);
    __this_cpu_write(cpu_cycle_count,0);
    __this_cpu_write(cpu_max_count,0);
    __this_cpu_write(cpu_min_count,0);

    __this_cpu_write(cpu_total_cost_time,0);
    __this_cpu_write(cpu_max_cost_time,0);
    __this_cpu_write(cpu_min_cost_time,0);
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

    // 触发PEBS Buffer 中断的阀值，按照0.9的阀值来设置触发
    //ds_p->pebs_thresh = ds_p->pebs_base + (pebs_max_num - pebs_max_num/10) * pebs_record_size ;
    ds_p->pebs_thresh = ds_p->pebs_max;

    ds_p->pebs_counter_reset[0] = -(int64_t)PERIOD;
    ds_p->pebs_counter_reset[1] = -(int64_t)PERIOD;


    // 写入到本地CPU变量中
    __this_cpu_write(cpu_ds_p, ds_p);

    print_ds_info();

    return true;
}


static irqreturn_t irq_handler(int irq, void *dev_id)
{
    pebs_pmi_handler();
    return IRQ_HANDLED;
}

static int pebs_vector = 0xf0;
unsigned long *vectors;

static void init_pebs_vector(void){
    printk(KERN_INFO "cpu-%d:init pebs vector.\n",get_cpu());

    /*
    gate_desc desc, *idt;

    vectors = (unsigned long *)kallsyms_lookup_name("used_vectors");
	if (!vectors)
		vectors = (unsigned long *)kallsyms_lookup_name("system_vectors");
	if (!vectors) {
		pr_err("Could not resolve system/used vectors. Missing CONFIG_KALLSYMS_ALL?\n");
		return;
	}

	while (test_bit(pebs_vector, vectors)) {
		if (pebs_vector == 0x40) {
			pr_err("No free vector found\n");
			return ;
		}
		pebs_vector--;
	}
	set_bit(pebs_vector, vectors);
	idt = (gate_desc *)kallsyms_lookup_name("idt_table");
	if (!idt) {
		pr_err("Could not resolve idt_table. Did you enable CONFIG_KALLSYMS_ALL?\n");
		return;
	}

	pack_gate(&desc, GATE_INTERRUPT, (unsigned long)pebs_pmi_handler,
			0, 0, 0);
	write_idt_entry(idt, pebs_vector,&desc);
    */
    
}

static void free_pebs_vector(void){
    //释放申请的中断
    if (vectors){
		clear_bit(pebs_vector, vectors);
    }
}

void pebs_pmi_handler(void){
    printk(KERN_INFO "cpu-%d:pebs_pmi_handler execute...\n",get_cpu());

    /*

    //todo: 加锁，防止和时间片调用入口冲突。。。。锁是CPU核级别，非全局

	// disable PMU，中断处理期间不计数
	wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);

	// global status ack
	wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, 1ULL << 62);
	
    // 调用 pebs_record_handler 来进行处理
    pebs_record_handler();

	// ack apic
	apic_eoi();

	apic_write(APIC_LVTPC, pebs_vector);

    wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 1);

    // todo：释放锁
    */
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

    // 初始化统计数据相关变量
    init_buffer_stat();

    //将Buffer首地址设置到IA32_DS_AREA寄存器中。
    uint64_t old_ds;
    rdmsrl(MSR_DS_AREA, old_ds);
    //将旧值暂存
	__this_cpu_write(cpu_old_ds, old_ds);
    wrmsrl(MSR_DS_AREA, (uint64_t)__this_cpu_read(cpu_ds_p));

    // 设置APIC处理向量号
    if(pebs_vector < 0x80){
        apic_write(APIC_LVTPC, pebs_vector);
    }

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

static int __init pebs_mod_init(void)
{
    // 初始化设置APIC
    init_pebs_vector();

    // 对每一个CPU进行初始化设置
    on_each_cpu(pebs_mod_init_each_cpu,NULL,1);

    // 设置内核钩子处理函数
    pebs_handler = pebs_record_handler;

    // 初始化定时器
    //init_pebs_timer();
    
    return 0;
}

/**
 * deprecated
*/
static void log_record(void* arg){
    char file_name[50];
    memset(file_name,'\0', sizeof(file_name));
    sprintf(file_name, "%s-%d%s",LOG_FILE_NAME_PREFFIX,get_cpu(),LOG_FILE_NAME_SUFFIX);
    printk(KERN_INFO "cpu-%d:file name is:=%s\n", get_cpu(), file_name);
    
    // 打开文件
    mode_t f_attrib = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IROTH | S_IWOTH | S_IXOTH;       
    struct file *filp = filp_open(file_name, O_RDWR|O_APPEND, f_attrib);
     
    if(IS_ERR(filp))
    {
        printk(KERN_INFO "cpu-%d:filp=%p\n", get_cpu(),filp);
        printk(KERN_INFO "cpu-%d:log file open failed. error_code=%ld\n",get_cpu(),PTR_ERR(filp));
        return;
    }else{
        printk(KERN_INFO "cpu-%d:log file open success...\n",get_cpu());
    }

    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p != NULL){
        uint64_t cur_addr = ds_p->pebs_base;
        uint64_t end_addr = ds_p->pebs_index;

        uint64_t* cur_p = cur_addr;
        //basic_info 和 mem_info各占32个字节，因此一条记录是64个字节
        uint32_t rec_count = (end_addr - cur_addr)/pebs_record_size;

        loff_t pos = 0;

        char total_rec_count[100];
        memset(total_rec_count,'\0', sizeof(total_rec_count));
        //jiffies_64记录了从开机以来时钟中断发生的次数
        sprintf(total_rec_count,"%lld:-----------cpu-%d:total record count=%d-----------\n",
                jiffies_64, get_cpu(),rec_count);
        //kernel_write(filp, total_rec_count, strlen(total_rec_count), &pos);

        uint32_t i = 0;
        uint32_t max_indx = rec_count * 8;
        while(i < max_indx){
            char data[150];
            memset(data,'\0', sizeof(data));
            // 输出record的值（按照8字节一条数据的方式）
            sprintf(data,"%lld:cpu-%d:address:%llx,PEBS record value:%llx\n",
                jiffies_64, get_cpu(),(cur_p+i),*(cur_p+i));
            //kernel_write(filp, data, strlen(data), &pos);
            i++;
        }
    }

    if(!IS_ERR(filp)){
        filp_close(filp,NULL);
    }
    
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

static void print_statistics(void){
    // 输出统计值
    uint64_t buffer_count = __this_cpu_read(cpu_buffer_count);
    uint64_t buffer_cycle_count = __this_cpu_read(cpu_buffer_cycle_count);
    uint64_t buffer_min_count = __this_cpu_read(cpu_buffer_min_count);
    uint64_t buffer_max_count = __this_cpu_read(cpu_buffer_max_count);

    uint64_t total_cost_time = __this_cpu_read(cpu_total_cost_time);
    uint64_t max_cost_time = __this_cpu_read(cpu_max_cost_time);
    uint64_t min_cost_time = __this_cpu_read(cpu_min_cost_time);
    if(buffer_count > 0){
        printk(KERN_INFO "cpu-%d:pebs buffer total record count:%lld,sample_count:%lld,avg:%lld, min:%lld, max:%lld; avg_cost_time(ns):%lld, min_cost_time(ns):%lld, max_cost_time(ns):%lld.\n",
                            get_cpu(), 
                            buffer_count,
                            buffer_cycle_count,
                            buffer_cycle_count > 0 ? (buffer_count/buffer_cycle_count) : 0,
                            buffer_min_count,
                            buffer_max_count,
                            buffer_cycle_count > 0 ? (total_cost_time/buffer_cycle_count) : 0,
                            min_cost_time,
                            max_cost_time
                            );
    }

    uint64_t total_count = __this_cpu_read(cpu_total_count);
    uint64_t cycle_count = __this_cpu_read(cpu_cycle_count);
    uint64_t min_count = __this_cpu_read(cpu_min_count);
    uint64_t max_count = __this_cpu_read(cpu_max_count);
    if(total_count > 0){
        printk(KERN_INFO "cpu-%d:pebs valid total record count:%lld,sample_count:%lld,avg:%lld, min:%lld, max:%lld.\n",
                            get_cpu(), 
                            total_count,
                            cycle_count,
                            cycle_count > 0? (total_count/cycle_count) : 0,
                            min_count,
                            max_count);
    }
}

static void pebs_mod_exit_each_cpu(void *arg){

    printk(KERN_INFO "cpu-%d:***********PEBS module exit start!*********\n",get_cpu());

    uint64_t val_addr;
    rdmsrl(MSR_DS_AREA,val_addr);
    printk(KERN_INFO "cpu-%d:rmmod: read value from MSR_DS_AREA, address=%llx\n",get_cpu(),val_addr);
    
    // 打印输出缓冲区的PEBS记录
    //print_pebs_buffer_records();

    // 打印输出统计数据
    print_statistics();

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

    //apic_write(APIC_LVTPC, __this_cpu_read(old_lvtpc));

    printk(KERN_INFO "cpu-%d:**********PEBS module exit success!********\n",get_cpu());

}


static void __exit pebs_mod_exit(void)
{
    int num = num_online_cpus();
    int cid = get_cpu();
    printk(KERN_INFO "cpu-%d: system has %d processor(s).\n", cid,num);

    pebs_handler = NULL;
    
    // 在所有CPU核心上按照核心顺序执行退出逻辑
    int i = 0;
    for (; i < num; i++){
        smp_call_function_single(i, pebs_mod_exit_each_cpu, NULL, 1);
    }

    free_pebs_vector();

    //del_pebs_timer();
}


static void print_pebs_record_single(uint64_t *address_p){
    unsigned short count = 4;
    unsigned short i = 0;
    for(; i<count; i++){
        printk(KERN_INFO "cpu-%d:address:%llx,pebs valid record value:%llx\n",get_cpu(),(address_p+i),*(address_p+i));
    }
}

/**
 * 获取时间戳（纳秒）
*/
static uint64_t get_current_time_ns(void){
    ktime_t now = ktime_get();
    return ktime_to_ns(now);
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
    uint64_t start_time = get_current_time_ns();
    //todo: 多核多进程&线程之间的竞争，加互斥锁避免
    /*
    if(pebs_handler == NULL){
        return;
    }else{
        pebs_handler = NULL;
    }
    */
    pebs_handler = NULL;

    //printk(KERN_INFO "cpu-%d:pebs_record_handler execute...",get_cpu());

    uint64_t count = 0;
    debug_store_t *ds_p = __this_cpu_read(cpu_ds_p);
    if(ds_p == NULL){
        printk(KERN_ERR "cpu-%d: get ds address from cpu local var failed.\n", get_cpu());
        pebs_handler = pebs_record_handler;
        return;
    }

    uint64_t start_addr = ds_p->pebs_base;
    uint64_t end_addr = ds_p->pebs_index;
    uint64_t buffer_count = (end_addr - start_addr)/pebs_record_size;

    if(buffer_count > 0){
        //printk(KERN_INFO "cpu-%d:pebs total record count:(%lld), pebs valid record count:(%lld).\n", get_cpu(),total_count,count);
        uint64_t buffer_count_o = __this_cpu_read(cpu_buffer_count);
        __this_cpu_write(cpu_buffer_count,buffer_count_o + buffer_count);

        uint64_t buffer_cycle_count_o = __this_cpu_read(cpu_buffer_cycle_count);
        __this_cpu_write(cpu_buffer_cycle_count,buffer_cycle_count_o + 1);

        uint64_t buffer_max_count_o = __this_cpu_read(cpu_buffer_max_count);
        if(buffer_count > buffer_max_count_o){
            __this_cpu_write(cpu_buffer_max_count,buffer_count);
        }

        uint64_t buffer_min_count_o = __this_cpu_read(cpu_buffer_min_count);
        if(buffer_min_count_o == 0 || buffer_count < buffer_min_count_o){
            __this_cpu_write(cpu_buffer_min_count,buffer_count);
        }
    }
    
    /*
    if(buffer_count>0){
        printk(KERN_INFO "cpu-%d:pebs total record count:%lld\n", get_cpu(),buffer_count);
    }*/
    
    // 只有一条记录就无需处理
    if(buffer_count <= 1){
        goto end;
    }

    uint64_t* cur_p_2 = end_addr - pebs_record_size; //branch_miss事件记录指针
    uint64_t* cur_p_1 =  end_addr - 2 * pebs_record_size;//cache_miss事件记录指针

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

        /*
        printk(KERN_INFO "cpu-%d:rec2:mem_addr_2=%llx;count_type_2=%llx;tsp_2=%llx;cur_p_1=%llx;cur_p_2=%llx\n", 
            get_cpu(),mem_addr_2,count_type_2,tsp_2,cur_p_1,cur_p_2);
        */
        
        while(cur_p_1>=start_addr){
            uint64_t mem_addr_1 = *(cur_p_1 + 1);
            uint64_t count_type_1 = *(cur_p_1 + 2);
            uint64_t tsp_1 = *(cur_p_1 + 3);

            //判断时间戳是否在300个cycle内，如果不在直接结束内层循环。
            if((tsp_2-tsp_1) > 300){
                goto fail_tag;
            }

            // 找cache_miss事件且内存地址最后两位为指定的值
            if(count_type_1 != CACHE_MISS_EVENT_ENUM || 
                (mem_addr_1 & 0x0fff) != CACHE_MISS_MEM_ADDR_LOW_2_BIT_VAL){
                cur_p_1 = cur_p_1 - pebs_record_size/8;
                continue;
            }

            // 比较地址差值是否在16个字节内
            uint64_t mem_addr_sub = mem_addr_2 > mem_addr_1 ? (mem_addr_2-mem_addr_1) : (mem_addr_1-mem_addr_2);
            if(mem_addr_sub > 16){
                cur_p_1 = cur_p_1 - pebs_record_size/8;
                continue;
            }

            // 找到符合条件的记录，并输出到日志
            count ++;
            print_pebs_record_single(cur_p_1);
            print_pebs_record_single(cur_p_2);
            goto succ_tag;
        }

        fail_tag:
            cur_p_2 = cur_p_2 - pebs_record_size/8;
            cur_p_1 = cur_p_2 - pebs_record_size/8;
            continue;

        succ_tag:
            cur_p_1 = cur_p_1 - pebs_record_size/8;
            cur_p_2 = cur_p_2 - pebs_record_size/8;
            continue;
    }

    end:
    if(count > 0){
        //printk(KERN_INFO "cpu-%d:pebs total record count:(%lld), pebs valid record count:(%lld).\n", get_cpu(),total_count,count);
        uint64_t total_count_o = __this_cpu_read(cpu_total_count);
        __this_cpu_write(cpu_total_count,total_count_o + count);

        uint64_t cycle_count_o = __this_cpu_read(cpu_cycle_count);
        __this_cpu_write(cpu_cycle_count,cycle_count_o + 1);

        uint64_t max_count_o = __this_cpu_read(cpu_max_count);
        if(count > max_count_o){
            __this_cpu_write(cpu_max_count,count);
        }

        uint64_t min_count_o = __this_cpu_read(cpu_min_count);
        if(min_count_o == 0 || count < min_count_o){
            __this_cpu_write(cpu_min_count,count);
        }
    }
    
    // 重置index以及计数器的值
    ds_p->pebs_index = ds_p->pebs_base;
    ds_p->pebs_counter_reset[0] = -(int64_t)PERIOD;
    ds_p->pebs_counter_reset[1] = -(int64_t)PERIOD;
    
    pebs_handler = pebs_record_handler;

    uint64_t end_time = get_current_time_ns();
    uint64_t cost_time =  end_time - start_time;

    if(buffer_count > 0){
        uint64_t total_cost_time_o = __this_cpu_read(cpu_total_cost_time);
        __this_cpu_write(cpu_total_cost_time,total_cost_time_o + cost_time);

        uint64_t max_cost_time_o = __this_cpu_read(cpu_max_cost_time);
        if(cost_time > max_cost_time_o){
            __this_cpu_write(cpu_max_cost_time,cost_time);
        }

        uint64_t min_cost_time_o = __this_cpu_read(cpu_min_cost_time);
        if(min_cost_time_o == 0 || cost_time < min_cost_time_o){
            __this_cpu_write(cpu_min_cost_time,cost_time);
        }
    }

}

module_init(pebs_mod_init);
module_exit(pebs_mod_exit);
