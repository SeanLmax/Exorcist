/*
 * @Date: 2023-05-18 11:22:19
 * @LastEditors: liuchang chang.liu@zhejianglab.com
 * @LastEditTime: 2023-06-08 14:18:21
 * @FilePath: /pebs/src/pebs_mod.h
 */

#ifndef PEBS_MOD_H
#define PEBS_MOD_H

enum PEBS_MOD_ERR_CODE {
    PEBS_MOD_OK = 0,
    PEBS_MOD_ERR,
    PEBS_MOD_DISABLE,
    PEBS_MOD_ENABLE,
    PEBS_MOD_LESS_CNT,
    PEBS_MOD_NULL
};

// extern int pebs_perf_record_data_start(void);
// extern int pebs_perf_record_data_stop(void);
// extern int pebs_perf_record_data_analysis(void);
extern void pebs_record_handler(void);

void pebs_pmi_handler(void);

#endif