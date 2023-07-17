import re
import os
import time

regex = re.compile(' +')
br_misp = 'br_misp_retired.near_taken:ppp'
l1_miss = 'mem_load_retired.l1_miss:ppp'

ip_group_interval_threshold = 20
ip_group_occurrence_threshold = 5

X8000 = int('8000000000000000', 16)
Xffff = int('ffffffffffffffff', 16)

'''
保存分组后的数据库, 以便快速分析多配置下的结果
database 数据结构 { path => processes }
'''
database = {}
def readData(path: str) -> dict:
    if path not in database:
        start_time = time.time()
        '''
        读取perf.log, 将记录按进程名分组
        processes 数据结构 { process => [ [proc, time, event, ip] ] }
        '''
        processes = {}
        with open(f'{path}/perf.log', 'r', encoding='utf-8') as perf_log:
            while True:
                line = perf_log.readline()
                if line:
                    text = line[:-1] # 去\n
                    line_list = regex.split(text)[1:] # 去行前空字符

                    if len(line_list) != 4: # 规范化行
                        line_list[0] = line_list[0] + line_list[1]
                        line_list.pop(1)
                    
                    proc,ts,event,ip = line_list
                    ts = float(ts[:-1])
                    event = event[:-1]
                    if ip == '':
                        ip = '0'
                    ip = parseNumber(int(ip, 16))
                    if proc not in processes:
                        processes[proc] = []
                    processes[proc].append([proc, ts, event, ip])
                else:
                    break
        end_time = time.time()
        print(f'end read {end_time - start_time}')
        database[path] = processes
        return processes
    else:
        return database[path]

'''
将数字规范在 -2^63 ~ 2^63-1
'''
def parseNumber(num: int) -> int:
    # if num >= X8000:
    #     return num - Xffff - 1
    return num

''' 
正数地址: cache miss发生的位置在branch miss发生位置的前20
负数地址: branch miss发生的位置在cache miss发生位置的前20
'''
def judge(cache_miss: list, branch_misp: list, now_process:str ) -> bool:
    if len(cache_miss) == 5 and cache_miss[4] == f'{ip_group_occurrence_threshold}{ip_group_interval_threshold}{now_process}':
        return False
    # if cache_miss < 0:
    #     return cache_miss - branch_misp >= 0 and cache_miss - branch_misp < ip_group_interval_threshold
    return branch_misp[3] - cache_miss[3] >= 0 and branch_misp[3] - cache_miss[3] < ip_group_interval_threshold

def analyse(path: str) -> tuple:
    total = (0, 0)
    ge_threshold_set = set()

    '''
    开始分析
    返回(records_count, total_ge_threshold_count)
    hits 数据结构 { process => (total_hit_count, total_ge_threshold_count, ge_threshold_details) }
    '''
    processes = readData(path)
    hits = {}
    with open(f'{path}/olog.log', 'w', encoding='utf-8') as olog:
        for p in processes:
            records = processes[p]
            records_length = len(records)

            '''
            根据分组好的进程分析命中情况, 并将满足要求的record中两个事件的IP组进行记录
            ip_group 数据结构 { (branch_misp, cache_miss) => count }
            '''
            ip_group = {}
            for i in range(records_length):
                ''' i -> branch_misp, j -> l1_miss '''
                if records[i][2] == br_misp:
                    # print(f'comparing {records[i]}:')
                    j = i + 1
                    while j < records_length and records[j][1] - records[i][1] <= 0.000005:
                        if records[j][2] == l1_miss and judge(records[j], records[i], p): 
                            _log = f'{records[i]}\t{records[j][:4]}\n'
                            olog.write(_log)
                            # print(_log[:-1])

                            # 统计IP组出现的次数
                            _ip_pair = (records[i][3], records[j][3])
                            if _ip_pair in ip_group:
                                ip_group[_ip_pair] = ip_group[_ip_pair] + 1
                            else:
                                ip_group[_ip_pair] = 1
                            
                            # 标记该条l1_miss为无效, 防止和其他br_misp重复统计
                            if len(records[j]) == 4:
                                records[j].append(f'{ip_group_occurrence_threshold}{ip_group_interval_threshold}{p}')
                            else:
                                records[j][4] = f'{ip_group_occurrence_threshold}{ip_group_interval_threshold}{p}'

                            break # 只记录符合要求的第一条
                        j = j + 1

            if len(ip_group) > 0: # IP组长度>0, 说明该进程存在命中情况
                '''
                相同的IP组出现的次数 >= 门限值时, 记录到hits中, 便于写出表格
                '''
                _total_hits_count = 0 # 总命中记录数
                _total_ge_threshold_count = 0 # 总达到门限值记录数
                _ge_threshold_detail = {} # 达到门限值的记录详情
                for k in ip_group:
                    _total_hits_count = _total_hits_count + ip_group[k]
                    if ip_group[k] >= ip_group_occurrence_threshold:
                        _total_ge_threshold_count = _total_ge_threshold_count + 1
                        
                        ge_threshold_set.add(ip_group[k]) # 将所有出现的门限值写入set

                        if ip_group[k] in _ge_threshold_detail:
                            _ge_threshold_detail[ip_group[k]] = _ge_threshold_detail[ip_group[k]] + 1
                        else:
                            _ge_threshold_detail[ip_group[k]] = 1
                
                total = (total[0] + _total_hits_count, total[1] + _total_ge_threshold_count)
                hits[p] = (_total_hits_count, _total_ge_threshold_count, _ge_threshold_detail)
                _log = f'{p} : total_hits({_total_hits_count}), total_ge{ip_group_occurrence_threshold}({_total_ge_threshold_count}), ge{ip_group_occurrence_threshold}_details({_ge_threshold_detail})\n'
                olog.write(_log)
                print(_log[:-1])


    '''
    ge_threshold_set排序, 写出表格
    '''
    with open(f'{path}/otable_{ip_group_occurrence_threshold}_{ip_group_interval_threshold}.log', 'w', encoding='utf-8') as otable:
        _sorted = sorted(ge_threshold_set)
        _head = ['process', 'total_hit_count', 'total_ge_threshold_count']
        _head.extend([f'hit_{item}' for item in _sorted])
        otable.write('\t'.join([str(item) for item in _head]) + '\n')

        for process in hits:
            _list = []
            for l in _sorted:
                if l in hits[process][2]:
                    _list.append(hits[process][2][l])
                else:
                    _list.append(0)
            _body = [process, hits[process][0], hits[process][1]]
            _body.extend(_list)
            otable.write('\t'.join([str(item) for item in _body]) + '\n')

    return total

def analyseDir(root: str) -> tuple:
    total = (0, 0)
    for path in os.listdir(root):
        count = analyse(f'{root}/{path}')
        total = (total[0] + count[0], total[1] + count[1])
        print(f'Finished Analyse {root}/{path} - {count}\n')
    return total

def inputConfig() -> bool:
    '''
    多配置分析
    '''
    global ip_group_occurrence_threshold
    global ip_group_interval_threshold
    try:
        ip_group_occurrence_threshold = int(input(f'Input ip_group_occurrence_threshold (default {ip_group_occurrence_threshold}, 0 to exit): '))
    except:
        print(f'Set to default value {ip_group_occurrence_threshold}')
    try:
        ip_group_interval_threshold = int(input(f'Input ip_group_interval_threshold (default {ip_group_interval_threshold}, 0 to exit): '))
    except:
        print(f'Set to default value {ip_group_interval_threshold}')
    return ip_group_occurrence_threshold != 0 and ip_group_interval_threshold != 0
        
if __name__ == '__main__':
    # print(parseNumber(18446744071930761944))
    # print(parseNumber(18446744071930761952))
    # print(checkIp(18446744071930761944, 18446744071930761952))
    while inputConfig():
        # print(f"\n{analyse('Kernel/00')}")
        # print(f"\n{analyseDir('Kernel')}")
        # print(f"\n{analyse('Source.o_Period/02')}")
        print(f"\n{analyseDir('Source.o_Period')}")