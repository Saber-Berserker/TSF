import atexit
import copy
import hashlib
import json
import os
import random
import re
import sys
import tracemalloc
from time import sleep
from typing import List, Tuple, Dict, Generator, TextIO

from loguru import logger
from pwn import process  # pwntools library

from topography import ODL_TopologyGraph
import Utils
from MutatorManager import MutatorManager
from data_structure.LLDP import TLV

# 一些文件路径配置(调用的时候需要以 Main.py 所在目录为根目录)
log_path: str = 'logs/'
scenario_path: str = 'scenarios/'
odl_root_dir: str = '~/integration-distribution/karaf/target/assembly/'
odl_classes_dir:str = '/home/ylc/integration-distribution/karaf/target/assembly/system/'
will_draw = False  # 是否绘制拓扑图

# 一些常量
tp: str = ''
sig: str = ''
os_username: str = 'ylc'
malicious_host: str = ''
delimited_length: Dict = {}
tlv_start_index: int = 14    # TLV 开始的索引值
swarm_extra_init_times: int = 5 - 3  # 总次数减种群遍历数=额外次数
fuzz_scenario_times: int = 15    # 模糊测试场景次数
fuzz_lldp_times: int = 50    # 模糊测试场景内单个 LLDP 包次数
get_ttl: str = 'h1 ping -c 3 h5'
original_stdout: TextIO

# 需要用到的全局变量
odl: process
mininet: process    # 因为涉及到外部链路，pingall 的时候需要等很久（ping不通），因此尽可能一次性多用 mininet，减少开销
mode_times: int = 0

odl_scenarios: List[List[str]]  # Floodlight 只有一种 LLDP 包
mutator_manager: MutatorManager
old_topography: ODL_TopologyGraph.ODLTopologyGraph
mutated_topography: List[ODL_TopologyGraph.ODLTopologyGraph] = []  # 设置为集合的话，会出现不可哈希的问题，会导致无法判断是否出现过

send_packets = 0
massages: Dict = {}
is_eval: bool = False
score: Dict = {}
env_constraint_enable: bool = True
oracle_times:Dict = {'error':0, 'topology':0, 'latency':0}
key = ''

def read_scenarios(scenario_file_path: str = 'opendaylight/') -> List[List[str]]:
    """读取场景文件，顺便把所有的源MAC给改了."""
    global scenario_path, tp, sig

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

                # 不改 tp 和 sig，这两算法还没弄明白
                lldp_list.append(line[:86] + tp + sig + line[-4:])
            scenarios.append(lldp_list)
    return scenarios


def lldp_data_capture(mininet_subprocess) -> tuple[str, str]:
    global malicious_host

    # mininet_subprocess.interactive()
    mininet_subprocess.sendline(f'{malicious_host} sudo python tools/Capture_ODL_LLDP_Data.py'.encode())
    temp = mininet_subprocess.recvregex(b'{.*}').decode()
    lldp_data: Dict = json.loads(re.search(r'\{.*?}', temp).group().strip())
    return lldp_data['TerminationPoint'], lldp_data['Sig']


def identify_odl_lldp(lldp: bytearray) -> Dict:
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

def update_odl_lldp(odl_lldp: bytes) -> bytes:
    """环境约束，更新 odl 的 LLDP 包."""
    global key
    tp_index = odl_lldp.find(bytes.fromhex('fe100026e100')) + 6
    if tp_index == -1:
        tp_index = 49
    signature = Utils.create_odl_sig(key, odl_lldp[tp_index:tp_index + 12])

    sig_index = odl_lldp.find(bytes.fromhex('fe140026e101')) + 6
    if sig_index == -1:
        sig_index = 67
    return odl_lldp[:sig_index] + bytes.fromhex(signature) + odl_lldp[-2:]


def send_mutated_lldp(new_odl_lldp: bytes):
    global malicious_host, delimited_length, mininet, send_packets

    new_odl_lldp = update_odl_lldp(new_odl_lldp)

    mininet.sendline(f'{malicious_host} sudo python tools/SendPacket.py {new_odl_lldp.hex()}'.encode())
    send_packets += 1

    logger.debug(f'Send packet: {new_odl_lldp}')
    return new_odl_lldp


def is_appeared(new_topography: ODL_TopologyGraph.ODLTopologyGraph) -> bool:
    """突变的拓扑图是否曾经出现过."""
    global original_stdout, log_path, mutated_topography

    logger.info("Checking if the mutated topology has appeared before.")
    logger.remove()     # 检查已有的拓扑图，不需要输出 log

    for old_topology in mutated_topography:
        if new_topography.compare_topologies(old_topology) is True:
            Utils.add_logger(log_path, original_stdout)
            return True

    Utils.add_logger(log_path, original_stdout)
    return False


def get_feedback(lldp_hex: str, chosen_swarm: int, operator_enum: int,
                 llpd_scenario: List[str], chosen_lldp_packet_index: int):
    global old_topography, odl, mutated_topography, will_draw, oracle_times
    flag = 0    # 0：没有异常，1：odl有异常，2：拓扑不一致，3：链路状态异常

    # 接收 odl 可能出现的 ERROR log
    odl_data = odl.recvrepeat(0.5)  # 等待 odl 返回的反馋信息

    # 测试 odl 的反馈信息
    if odl.poll() is not None:
        logger.warning("Interesting, odl has exited.")

        atexit.unregister(Utils.close_opendaylight)
        Utils.close_opendaylight(odl)
        init_odl(mininet)
        atexit.register(Utils.close_opendaylight, odl)

        flag = 1

    # 本可不需要，直接 elif 就行了，但是现在程序还是覆盖 bug 不全，所以需要这个来判断是否需要继续
    new_topography = ODL_TopologyGraph.ODLTopologyGraph()
    ODL_TopologyGraph.build_topology_graph(new_topography)


    # 测试拓扑图一致性
    if old_topography.compare_topologies(new_topography) is False:
        # 判断是否曾经出现过相同的变异拓扑图
        if is_appeared(new_topography):    # 不能用 in，in 是比较的 networkx 的内存地址，要修改
            logger.debug("Same topology. May be Interesting. the LLDP packet is:\n {}", lldp_hex)
        else:
            flag = 2

        old_topography = new_topography

    if flag == 1:
        logger.warning("Interesting! odl raise something. The LLDP packet is:\n {}", lldp_hex)
        oracle_times['error'] += 1
    elif flag == 2:
        logger.warning("Interesting! Topological inconsistency. The LLDP packet is:\n {}", lldp_hex)
        oracle_times['topology'] += 1
    # else:   # mininet 反正ping不通，无法测试链路状态
    #     mininet.sendline(get_ttl.encode())
    #     per_recv = re.search(r'(\d+)% packet loss, time (\d+)ms',
    #                          mininet.recvregex(rb"\d+% packet loss, time \d+ms").decode())
    #     if int(per_recv.group(1)) >= 75 or int(per_recv.group(2)) >= 17000:
    #         flag = 3
    #         logger.warning("Interesting! High network link latency. The LLDP packet is:\n {}", lldp_hex)

    if flag > 0:    # 记录、反馈
        if will_draw:
            # 图形化看看哪里不同
            new_topography.display_topology()

        mutated_topography.append(new_topography)

        mutator_manager.operators_eff[chosen_swarm][operator_enum][1] += 1  # 记录有效变异
        # TODO: 是否需要写回文件作为新的种子文件？

        # 有效变异包添加回场景，用于下次变异——种子回馈
        tmp_scenario = copy.deepcopy(llpd_scenario)
        tmp_scenario[chosen_lldp_packet_index] = lldp_hex

        odl_scenarios.append(tmp_scenario)

    else:
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

        try:
            new_lldp_fuzz_data = mutate_lldp_packet(lldp_scenario[chosen_lldp_packet_index].strip(),
                                                    init_swarm_generator)
            for i in range(len(new_lldp_fuzz_data[0])):
                try:
                    new_lldp_fuzz_data[0][i] = send_mutated_lldp(new_lldp_fuzz_data[0][i])
                    sleep(1.3)  # 等待一段时间，等待反馈信息，这个数字很影响整体系统的速度
                    get_feedback(new_lldp_fuzz_data[0][i].hex(), new_lldp_fuzz_data[1], new_lldp_fuzz_data[2][i],
                                 lldp_scenario, chosen_lldp_packet_index)
                except Exception as e:
                    logger.error("Sending mutated packet raise error: {}", e)
        except Exception as e:
            logger.error("Mutating packet raise error: {}", e)
        else:
            # 没有异常发送执行的代码
            pass
        finally:
            mutator_manager.update_MOPT()


def init_odl(mininet_subprocess: process = None):
    """
    初始化 odl 和 Mininet(如果没有的话)，并且获取 odl 的一些密钥数据.
    :param mininet_subprocess:
    :return: odl, mininet
    """
    global os_username, tp, sig, odl, mininet, odl_root_dir, is_eval


    # 启动 opendaylight
    odl = Utils.start_opendaylight(os_username, odl_root_dir, is_eval)
    atexit.register(Utils.close_opendaylight, odl)
    # odl_subprocess.interactive()


    if mininet_subprocess is None:
        # Mininet 网络拓扑初始化
        mininet = Utils.start_mininet(3, odl)
        atexit.register(Utils.close_mininet, mininet)
    else:
        mininet = mininet_subprocess
    del mininet_subprocess

    # mininet_subprocess.interactive()

    tp, sig = lldp_data_capture(mininet)
    print(tp+sig)


def start_fuzzing(config: Dict, stdout: TextIO, eval_mode: bool):
    """
    开始 odl 模糊测试.
    :return:
    """
    global odl, mininet, src_mac, mode_times, swarm_extra_init_times, fuzz_scenario_times,\
        fuzz_lldp_times, os_username, malicious_host, delimited_length, tlv_start_index, mutated_topography,\
        old_topography, mutator_manager, odl_scenarios, original_stdout, will_draw, is_eval, score, env_constraint_enable,\
        key, odl_root_dir, odl_classes_dir

    # 获取参数，如果没有传入则使用原本全局的值
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
    key = config['odl_key']
    odl_root_dir = config['ODL_ROOT_DIR']
    odl_classes_dir = config['odl_classes_dir']

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

    init_odl()

    logger.debug("odl and Mininet started.")    # odl没有输出信息

    # 读取场景文件
    odl_scenarios = read_scenarios('opendaylight/')
    logger.info("Scenarios loaded.")
    logger.trace("odl scenarios: {}", odl_scenarios)

    # 后续需要使用的一些变量或者对象
    mutator_manager = MutatorManager(mininet, malicious_host, delimited_length, config['lldp_mutation_iteration_max'])
    init_swarm_generator = mutator_manager.select_swarm_init(swarm_extra_init_times)


    # 初始化拓扑图数据结构
    old_topography = ODL_TopologyGraph.ODLTopologyGraph()
    ODL_TopologyGraph.build_topology_graph(old_topography)

    if will_draw:
        # 画出初始拓扑图
        old_topography.display_topology()
    mutated_topography.append(old_topography)
    logger.info("Initial topology graph has been built.")

    if is_eval is True:
        # 先清理之前的覆盖率数据
        Utils.clear_old_coverage_data("evaluation/odl-coverage.exec", "evaluation/odl-coverage.json")
        logger.info("Old coverage data cleared.")
        # 首次保存未 Fuzzing 的覆盖率数据
        Utils.save_coverage_score("Odl", odl_classes_dir, "evaluation/jacoco/lib/jacococli.jar",
                                  "evaluation/odl-coverage.exec",
                                  "evaluation/odl-report.xml", "evaluation/odl-coverage.json")

    for _ in range(mode_times):  # 模式测试次数

        for __ in range(fuzz_scenario_times):  # 测试场景
            logger.info('\n\n' + '-' * 100 + '\n')

            logger.info("Fuzzing odl LLDP scenario.")
            chosen_odl_scenario = random.choice(odl_scenarios)  # TODO: 是否需要概率选择？
            logger.info('Chosen odl scenario index: {}', odl_scenarios.index(chosen_odl_scenario))
            fuzz_scenario(chosen_odl_scenario, init_swarm_generator)


            # 重启 mininet
            atexit.unregister(Utils.close_mininet)
            Utils.close_mininet(mininet)
            mininet = Utils.start_mininet(3, odl)
            atexit.register(Utils.close_mininet, mininet)
            logger.debug("odl and Mininet started. Message: {}", odl.recvrepeat(0.8).decode())

            mutator_manager.mininet_subprocess = mininet
            old_topography.graph.clear()
            ODL_TopologyGraph.build_topology_graph(old_topography)  # 重启 mininet 后，需要重新构建拓扑图

            if is_eval is True:
                Utils.save_coverage_score("Odl", odl_classes_dir, "evaluation/jacoco/lib/jacococli.jar",
                                          "evaluation/odl-coverage.exec",
                                          "evaluation/odl-report.xml", "evaluation/odl-coverage.json")

        # 重启 odl
        atexit.unregister(Utils.close_opendaylight)
        Utils.close_opendaylight(odl)
        init_odl(mininet)
        atexit.register(Utils.close_opendaylight, odl)

    logger.info(f"All Send times: {send_packets}")
    logger.info(f'Oracle times: {oracle_times}')