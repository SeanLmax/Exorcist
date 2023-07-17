/*
 * @Date: 2023-05-29 16:39:19
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-05-29 17:34:25
 * @FilePath: /pebs/src/pebs_timer.c
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include "pebs_timer.h"

/* 定义定时器 */
struct timer_list timer; 


/* 定时器回调函数 */
void timer_callback_func(struct timer_list *arg)
{
    printk(KERN_INFO "cpu-%d: timer_callback_func execute...\n", get_cpu());

    //如果需要定时器周期性运行的话就使用 mod_timer函数重新设置超时值并且启动定时器。
    mod_timer(&timer, jiffies_64 + msecs_to_jiffies(2000));
}

void init_pebs_timer(void){
    timer_setup(&timer, timer_callback_func, 0);
    timer.expires = jiffies_64 + msecs_to_jiffies(2000);    //定时时间
    add_timer(&timer);

}

 /* 删除定时器 */
void del_pebs_timer(void){
    del_timer_sync(&timer);
}