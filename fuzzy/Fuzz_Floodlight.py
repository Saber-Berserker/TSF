import atexit
import copy
import json
import os
import random
import re
import sys
import tracemalloc  # 用于内存泄漏检测
import hashlib
from time import sleep
from typing import List, Tuple, Dict, Generator, TextIO

from loguru import logger
from pwn import process  # pwntools library

from topography import FLT_TopologyGraph
import Utils
from MutatorManager import MutatorManager
from data_structure.LLDP import TLV

# 一些文件路径配置
log_path: str = 'logs/'
scenario_path: str = 'scenarios/'
trigger_packet_file = 'logs/trigger_packet.txt'
will_draw = False  # 是否绘制拓扑图

# 一些常量
src_mac: str = ''
controller_id: str = ''
os_username: str = 'ylc'
malicious_host: str = ''
delimited_length: Dict = {'onos_1': 90,'floodlight': 160,'onos_2': 290}  # 根据长度判断是否是哪个控制器的哪种 LLDP 包（ONOS有两个）, 90(84), 160(150), 290(278) 分别区分 ONOS 1, Floodlight, ONOS 2
tlv_start_index: int = 14    # TLV 开始的索引值
swarm_extra_init_times: int = 5 - 3  # 总次数减种群遍历数=额外次数
fuzz_scenario_times: int = 15    # 模糊测试场景次数
fuzz_lldp_times: int = 50    # 模糊测试场景内单个 LLDP 包次数
get_latency: str = 'h1 ping -c 3 h5'
original_stdout: TextIO

# 需要用到的全局变量
flt: process
mininet: process    # 因为涉及到外部链路，pingall 的时候需要等很久（ping不通），因此尽可能一次性多用 mininet，减少开销
mode_times: int = 0

flt_scenarios: List[List[str]]  # Floodlight 只有一种 LLDP 包
mutator_manager: MutatorManager
old_topography: FLT_TopologyGraph.FLTTopologyGraph
mutated_topography: List[FLT_TopologyGraph.FLTTopologyGraph] = []  # 设置为集合的话，会出现不可哈希的问题，会导致无法判断是否出现过

send_packets = 0
massages: Dict = {}
is_eval: bool = False
score: Dict = {}
env_constraint_enable: bool = True
oracle_times:Dict = {'error':0, 'topology':0, 'latency':0}

def read_scenarios(scenario_file_path: str = 'floodlight/') -> List[List[str]]:
    """读取场景文件，顺便把所有的源MAC给改了."""
    global scenario_path, src_mac, controller_id

    scenarios: List[List[str]] = []
    for filename in os.listdir(scenario_path + scenario_file_path):
        if os.path.isdir(scenario_path + scenario_file_path + filename):
            continue
        with open(scenario_path + scenario_file_path + filename, 'r') as f:
            lldp_list: List[str] = []
            while True:
                line = f.readline()
                if line == '':
                    break

                # 读取场景文件，顺便把所有的源MAC和ControllerID给改了， TODO: 时间戳要不要改？
                if line[28:28+16] == '2000060400020000':    # BDDP 包
                    # lldp_list.append(line[:12] + src_mac + line[24:])   # 不修改 controllerID，可体现bug
                    lldp_list.append(line[:12] + src_mac + line[24:108] + controller_id + line[128:])
                else:   # LLDP 包
                    lldp_list.append(line[:12] + src_mac + line[24:92] + controller_id + line[112:])
            scenarios.append(lldp_list)
    return scenarios


def lldp_data_capture(mininet_subprocess) -> Dict:
    global malicious_host

    # mininet_subprocess.interactive()
    mininet_subprocess.sendline(f'{malicious_host} sudo python tools/Capture_Floodlight_LLDP_Data.py'.encode())
    temp = mininet_subprocess.recvregex(b'{.*}').decode()
    lldp_data: Dict = json.loads(re.search(r'\{.*?}', temp).group().strip())
    return lldp_data


def identify_flt_lldp(lldp: bytearray) -> Dict:
    """识别 LLDP 包."""
    global tlv_start_index

    dst_mac: bytearray = lldp[:6]
    sr_mac: bytearray = lldp[6:12]
    ether_type: bytearray = lldp[12:14]

    lldp_index = tlv_start_index     # TLV 开始的索引值
    tlvs: List[TLV] = []
    while lldp_index < len(lldp):
        if lldp_index + 2 <= len(lldp):  # 防止索引越界，字节补 0
            tmp_tlv = TLV(lldp[lldp_index:lldp_index + 2])  # 这个就算后面那个大于长度很多也不会报错，因为是切片
        else:  # 防止索引越界，字节补 0
            lldp.append(0)  # while管理了一个，因此只可能缺少一位
            tmp_tlv = TLV(lldp[lldp_index:lldp_index + 2])
        if lldp_index + 2 + tmp_tlv.get_value_length() <= len(lldp):  # 防止索引越界
            tmp_tlv.set_value(lldp[lldp_index + 2:lldp_index + 2 + tmp_tlv.get_value_length()])
        else:
            if lldp_index + 2 == len(lldp):     # 此时一般是遇到了结束 TLV，没有value字段，索引刚好为长度
                break
            deviation = lldp_index + 2 + tmp_tlv.get_value_length() - len(lldp)
            lldp.extend([0] * deviation)
            del deviation

            tmp_tlv.set_value(lldp[lldp_index + 2:lldp_index + 2 + tmp_tlv.get_value_length()])

        lldp_index += 2 + tmp_tlv.get_value_length()
        tlvs.append(tmp_tlv)

    tmp_dict = {
        "dst_mac": dst_mac,
        "src_mac": sr_mac,
        "ether_type": ether_type,
        "tlvs": tlvs
    }
    return tmp_dict

def update_flt_lldp():
    """语法变异，更新 flt 的 LLDP 包."""
    pass


def send_mutated_lldp(new_flt_lldp: bytes):
    global malicious_host, delimited_length, mininet, send_packets

    if (len(new_flt_lldp) < delimited_length['onos_1']
                or delimited_length['onos_1'] < len(new_flt_lldp) < delimited_length['floodlight']):  # onos 或者floodlight 的普通 LLDP 包
        mininet.sendline(f'{malicious_host} sudo python tools/SendPacket.py {new_flt_lldp.hex()}'.encode())
        send_packets += 1

    # 下面侧重语法变异了，或者添加 TLV变异？
    # else:   # flt 的 LLDP 包
    #     lldp_data:Dict = identify_flt_lldp(bytearray.fromhex(new_flt_lldp.hex()))
    #     original_flt_data = identify_flt_lldp(bytearray.fromhex(original_flt_lldp))
    #     new_flt_lldp = update_flt_lldp(lldp_data, original_flt_data)
    #
    #     mininet.sendline(f'{malicious_host} sudo python tools/SendPacket.py {new_flt_lldp.hex()}'.encode())

    logger.debug(f'Send packet: {new_flt_lldp}')
    return new_flt_lldp


def is_appeared(new_topography: FLT_TopologyGraph.FLTTopologyGraph) -> bool:
    """突变的拓扑图是否曾经出现过."""
    global original_stdout, log_path

    logger.info("Checking if the mutated topology has appeared before.")
    logger.remove()     # 检查已有的拓扑图，不需要输出 log

    for old_topology in mutated_topography:
        if new_topography.compare_topologies(old_topology) is True:
            Utils.add_logger(log_path, original_stdout)
            return True

    Utils.add_logger(log_path, original_stdout)
    return False


def get_feedback(lldp_hex: str, chosen_swarm: int, operator_enum: int,
                 llpd_scenario: List[str], chosen_lldp_packet_index: int, tmp_packets: List[str]):
    global old_topography, flt, will_draw, oracle_times
    flag = 0    # 0：没有异常，1：flt有异常，2：拓扑不一致，3：链路状态异常

    # 接收 flt 可能出现的 ERROR log
    flt_data = flt.recvrepeat(0.5)  # 等待 flt 返回的反馋信息

    # 测试 flt 的反馈信息
    if flt.poll() is not None:
        logger.warning("Interesting, flt has exited.")

        atexit.unregister(Utils.close_floodlight)
        Utils.close_floodlight(flt)
        init_flt(mininet)
        atexit.register(Utils.close_floodlight, flt)

        flag = 1

    # TODO: 针对Floodlight的反馈信息进行完全的反馈处理
    for line in flt_data.decode().split('\n'):
        catches = re.match(r'^\d+-\d+-\d+\s+\d+:\d+:\d+\.\d+\s+(\w+)\s+\[(.*?)]\s+(.*)$', line)
        if catches is None:
            continue
        else:
            problem = re.sub(r'\d{6,}', '', catches.group(3))  # 2是日志模块名
            hash_code = hashlib.sha1(problem.encode()).hexdigest()
        if 'ERROR' in catches.group(1) and massages.get(hash_code, 0) < 5:
            logger.warning("flt find error:\n{}", line)
            flag = 1
            if massages.get(hash_code, 0) == 0: # 可能没有该键
                massages[hash_code] = 1
            else:
                massages[hash_code] += 1
        elif 'WARN' in catches.group(1) and massages.get(hash_code, 0) < 5:
            logger.warning("flt find warn:\n{}", line)
            if massages.get(hash_code, 0) == 0: # 可能没有该键
                massages[hash_code] = 1
            else:
                massages[hash_code] += 1

    # 本可不需要，直接 elif 就行了，但是现在程序还是覆盖 bug 不全，所以需要这个来判断是否需要继续
    new_topography = FLT_TopologyGraph.FLTTopologyGraph()
    FLT_TopologyGraph.build_topology_graph(new_topography)


    # 测试拓扑图一致性
    if old_topography.compare_topologies(new_topography) is False:
        # 判断是否曾经出现过相同的变异拓扑图
        if is_appeared(new_topography):    # 不能用 in，in 是比较的 networkx 的内存地址，要修改
            logger.debug("Same topology. May be Interesting. the LLDP packet is:\n {}", lldp_hex)
        else:
            flag = 2

        old_topography = new_topography

    record_str:str = ''

    if flag == 1:
        logger.warning("Interesting! flt raise something. The LLDP packet is:\n {}", lldp_hex)
        record_str = 'Raise something'
        oracle_times['error'] += 1
    elif flag == 2:
        logger.warning("Interesting! Topological inconsistency. The LLDP packet is:\n {}", lldp_hex)
        record_str = 'Topological inconsistency'
        oracle_times['topology'] += 1

    else:   # 最后测试链路状态（测试两次再确定，以免误判）
        temp = 0
        while temp < 2:
            mininet.clean()
            mininet.sendline(get_latency.encode())
            per_recv = re.search(r'(\d+)% packet loss, time (\d+)ms',
                                 mininet.recvregex(rb"\d+% packet loss, time \d+ms").decode())
            if per_recv is None:
                flag = 3  # 直接就是断链路
                oracle_times['latency'] += 1
                break
            elif int(per_recv.group(1)) >= 75 or int(per_recv.group(2)) >= 17000:  # 丢包率和时延
                temp += 1
                sleep(0.5)
            else:
                break

        if temp >= 2:
            flag = 3
            logger.warning("Interesting! High network link latency. The LLDP packet is:\n {}", lldp_hex)
            oracle_times['latency'] += 1
        del temp

    if flag > 0:    # 记录、反馈
        if will_draw:
            # 图形化看看哪里不同
            new_topography.display_topology()

        # mutated_topography.append(new_topography)   # 尝试是否是该原因导致内存问题

        mutator_manager.operators_eff[chosen_swarm][operator_enum][1] += 1  # 记录有效变异
        # TODO: 是否需要写回文件作为新的种子文件？

        # 记录有效包
        # tmp_packets.append(record_str + ': ' + lldp_hex)

        # 有效变异包添加回场景，用于下次变异——种子回馈
        # tmp_scenario = copy.deepcopy(llpd_scenario)
        # tmp_scenario[chosen_lldp_packet_index] = lldp_hex
        #
        # flt_scenarios.append(tmp_scenario)
        # tmp_packets[0] = '1'

    else:
        # tmp_packets.append(lldp_hex)
        logger.debug("No interesting. the LLDP packet is:\n {}", lldp_hex)


    # print('test')

    mutator_manager.operators_eff[chosen_swarm][operator_enum][0] += 1  # 记录总变异次数
    return


def mutate_lldp_packet(chosen_lldp_packet: str, init_swarm_generator: Generator) -> Tuple[List[bytes], int, List[int]]:

    logger.info('Mutating packet: {}', chosen_lldp_packet)

    try:
        chosen_swarm = next(init_swarm_generator)  # 使用next()方法获取迭代器、生成器的下一个元素
    except StopIteration:
        chosen_swarm = mutator_manager.select_best_swarm()

    return mutator_manager.swarm_fuzz(chosen_swarm, chosen_lldp_packet)


def fuzz_scenario(lldp_scenario: List[str], init_swarm_generator: Generator):
    for ___ in range(fuzz_lldp_times):  # 模糊测试场景内 LLDP 包次数
        chosen_lldp_packet_index: int = random.choice(range(len(lldp_scenario)))  # TODO: 概率选择场景中的一个 LLDP 包
        tmp_packet: List[str] = ['0', lldp_scenario[chosen_lldp_packet_index].strip()]

        try:
            new_lldp_fuzz_data = mutate_lldp_packet(lldp_scenario[chosen_lldp_packet_index].strip(),
                                                    init_swarm_generator)
            for i in range(len(new_lldp_fuzz_data[0])):
                try:
                    new_lldp_fuzz_data[0][i] = send_mutated_lldp(new_lldp_fuzz_data[0][i])
                    sleep(1.2)  # 等待一段时间，等待反馈信息，这个数字很影响整体系统的速度
                    get_feedback(new_lldp_fuzz_data[0][i].hex(), new_lldp_fuzz_data[1], new_lldp_fuzz_data[2][i],
                                 lldp_scenario, chosen_lldp_packet_index, tmp_packet)
                except Exception as e:
                    logger.error("Sending mutated packet raise error: {}", e)
        except Exception as e:
            logger.error("Mutating packet raise error: {}", e)
        else:
            # 没有异常发送执行的代码
            pass
        finally:
            # if tmp_packet[0] == '1':    # 有效变异，记录下来所有发送的包
            #     with open('tmp_packets.txt', 'a+') as f:
            #         f.write('\n'+ '-'*100 + '\n')
            #         for packet in tmp_packet:
            #             if packet == '1':
            #                 continue
            #             f.write(packet + '\n')
            mutator_manager.update_MOPT()


def init_flt(mininet_subprocess: process = None):
    """
    初始化 flt 和 Mininet(如果没有的话)，并且获取 flt 的一些密钥数据.
    :param mininet_subprocess:
    :return: flt, mininet
    """
    global os_username, src_mac, controller_id, flt, mininet, is_eval


    # 启动 floodlight
    flt = Utils.start_floodlight(os_username, is_eval)
    atexit.register(Utils.close_floodlight, flt)
    # flt_subprocess.interactive()


    if mininet_subprocess is None:
        # Mininet 网络拓扑初始化
        mininet = Utils.start_mininet(2, flt)
        atexit.register(Utils.close_mininet, mininet)
    else:
        mininet = mininet_subprocess
    del mininet_subprocess

    # mininet_subprocess.interactive()

    flt.recvrepeat(1.0)  # 处理 pingall 后 floodlight 的大量输出信息

    # 获取 flt 的一些密钥数据，此时 flt 会发送几个 LLDP 包，可以初始一下我们的拓扑图数据结构，让一些单向的交换机链路变成双向的
    packet_json = lldp_data_capture(mininet)
    src_mac, controller_id = packet_json['SrcMac'], packet_json['ControllerId']

def start_fuzzing(config: Dict, stdout: TextIO, eval_mode: bool):
    """
    开始 flt 模糊测试.
    :param config:
    :param stdout:
    :param eval_mode:
    :return:
    """
    global flt, mininet, src_mac, controller_id, mode_times, swarm_extra_init_times, fuzz_scenario_times,\
        fuzz_lldp_times, os_username, malicious_host, delimited_length, tlv_start_index, mutated_topography,\
        old_topography, mutator_manager, flt_scenarios, original_stdout, will_draw, is_eval, score, env_constraint_enable

    tracemalloc.start()

    # 获取参数，如果没有传入则使用原本全局的值
    malicious_host = config['malicious_host']
    os_username = config['os_username']
    delimited_length = config['delimited_length']
    tlv_start_index = config['tlv_start_index']
    swarm_extra_init_times = config['swarm_extra_init_times']
    fuzz_scenario_times = config['fuzz_scenario_times']
    fuzz_lldp_times = config['fuzz_lldp_times']
    will_draw = config['will_draw']
    env_constraint_enable = config['env_constraint_enable']


    original_stdout = stdout
    is_eval = eval_mode

    # 用户输入模糊测试场景次数
    try:
        logger.info("Please input the mode fuzzing times:")
        mode_times = int(input())    # 这里实际上被替换成了 pwn 库中的 readline() 函数，暂时不知道怎么解决
    except ValueError:
        logger.error("Invalid input.")
        sys.exit(1)

    logger.info("TSFuzzer started.")

    init_flt()

    logger.debug("flt and Mininet started. Message: {}", flt.recvrepeat(timeout=0.8).decode())    # recvall() 会一直等待，直到超时（会强制退出flt，但是flt的服务不会退出）

    # 读取场景文件
    flt_scenarios = read_scenarios('floodlight/')
    logger.info("Scenarios loaded.")
    logger.trace("flt scenarios: {}", flt_scenarios)

    # 后续需要使用的一些变量或者对象
    mutator_manager = MutatorManager(mininet, malicious_host, delimited_length, config['lldp_mutation_iteration_max'])
    init_swarm_generator = mutator_manager.select_swarm_init(swarm_extra_init_times)


    # 初始化拓扑图数据结构
    old_topography = FLT_TopologyGraph.FLTTopologyGraph()
    FLT_TopologyGraph.build_topology_graph(old_topography)

    if will_draw:
        old_topography.display_topology()
    mutated_topography.append(old_topography)
    logger.info("Initial topology graph has been built.")

    if is_eval is True:
        # 先清理之前的覆盖率数据
        Utils.clear_old_coverage_data("evaluation/flt-coverage.exec", "evaluation/flt-coverage.json")
        logger.info("Old coverage data cleared.")
        # 首次保存未 Fuzzing 的覆盖率数据
        Utils.save_coverage_score("Floodlight", config['flt_classes_dir'], "evaluation/jacoco/lib/jacococli.jar",
                                  "evaluation/flt-coverage.exec",
                                  "evaluation/flt-report.xml", "evaluation/flt-coverage.json")

    for _ in range(mode_times):  # 模式测试次数

        for __ in range(fuzz_scenario_times):  # 测试场景
            logger.info('\n\n' + '-' * 100 + '\n')

            logger.info("Fuzzing flt LLDP scenario.")
            chosen_flt_scenario = random.choice(flt_scenarios)  # TODO: 是否需要概率选择？
            logger.info('Chosen flt scenario index: {}', flt_scenarios.index(chosen_flt_scenario))
            fuzz_scenario(chosen_flt_scenario, init_swarm_generator)

            # 重启 mininet
            atexit.unregister(Utils.close_mininet)
            Utils.close_mininet(mininet)
            mininet = Utils.start_mininet(2, flt)
            atexit.register(Utils.close_mininet, mininet)
            logger.debug("flt and Mininet started. Message: {}", flt.recvrepeat(0.8).decode())

            mutator_manager.mininet_subprocess = mininet
            old_topography.graph.clear()
            FLT_TopologyGraph.build_topology_graph(old_topography)  # 重启 mininet 后，需要重新构建拓扑图

            if is_eval is True:
                Utils.save_coverage_score("Floodlight", config['flt_classes_dir'], "evaluation/jacoco/lib/jacococli.jar",
                                     "evaluation/flt-coverage.exec",
                                     "evaluation/flt-report.xml", "evaluation/flt-coverage.json")

        # 重启 flt
        atexit.unregister(Utils.close_floodlight)
        Utils.close_floodlight(flt)
        init_flt(mininet)
        atexit.register(Utils.close_floodlight, flt)

    logger.info(f"All Send times: {send_packets}")
    # 调试下内存使用情况
    snapshot = tracemalloc.take_snapshot()
    logger.info(f'This is length of topography saved: {len(mutated_topography)}')
    stats = snapshot.statistics("lineno")
    logger.info("memory usage statistics:")
    for stat in stats[:10]:
        logger.info(stat)

    logger.info(f'Oracle times: {oracle_times}')