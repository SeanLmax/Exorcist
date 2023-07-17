import os

ip_group_threshold = 5
stat_ip_group_occurrence_min = ip_group_threshold
stat_ip_group_occurrence_max = 10
ip_group_interval_min = 15
ip_group_interval_max = 20

def stat(path: str, process: str):
    '''
    根据路径读取配置要求的otable.log
    otable 的格式 [ process, total_hit_count, total_ge_threshold_count, [hits] ]
    '''
    with open(f'{path}/stat_{process}_{stat_ip_group_occurrence_min}-{stat_ip_group_occurrence_max}_{ip_group_interval_max}-{ip_group_interval_min}.log', 'w', encoding='utf-8') as ostat:
        # 写出表头
        ohead = ['interval/ip_group count']
        numhead = [x for x in range(stat_ip_group_occurrence_min, stat_ip_group_occurrence_max + 1)]
        for y in numhead:
            ohead.append(f'>={y}')
        ohead.extend(['total_hit_count'])
        ostat.write('\t'.join(ohead) + '\n')

        # 读取数据
        for interval in range(ip_group_interval_max, ip_group_interval_min - 1, -1):
            head = None
            body = None
            try:
                with open(f'{path}/otable_{ip_group_threshold}_{interval}.log', 'r', encoding='utf-8') as otable:
                    full = otable.readlines()
                    head = full[0][:-1].split('\t')
                    for line in full[1:]:
                        data = line[:-1].split('\t')
                        if data[0] == process:
                            body = data
                            break
            except FileNotFoundError:
                print(f'Warning: File {path}/otable_{ip_group_threshold}_{interval}.log not found, skip.')

            if head == None or body == None: # 如果某一 interval 对应的 otable 无数据, 则跳过该 interval
                continue
            
            obody = [f'interval_{interval}']
            # 处理数据
            for j in range(stat_ip_group_occurrence_min, stat_ip_group_occurrence_max + 1):
                sum = 0
                for k in range(3, len(head)):
                    if int(head[k].replace('hit_', '')) >= j:
                        sum = sum + int(body[k])
                obody.append(str(sum))
            obody.extend([body[1]])
            ostat.write('\t'.join(obody) + '\n')

def statDir(root: str, process: str):
    for path in os.listdir(root):
        stat(f'{root}/{path}', process)
        print(f'Finished Stat {root}/{path}\n')

if __name__ == '__main__':
    # stat('Kernel/01', 'cc1')
    # statDir('Kernel', 'cc1')
    # stat('Source.o/01', 'Source.o')
    statDir('Source.o_Period', 'Source.o')