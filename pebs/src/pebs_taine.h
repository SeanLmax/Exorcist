/*
 * @Date: 2023-07-12 13:53:42
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-07-12 16:29:54
 * @FilePath: /pebs/src/pebs_taine.h
 */
#ifndef PEBS_TAINE_H
#define PEBS_TAINE_H

void pebs_taine_analyze(struct task_struct * task,uint64_t start_addr, uint64_t end_addr);

#endif