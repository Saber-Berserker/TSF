import atexit
import copy
import json
import os
import random
import sys
import time
import re
import hashlib
from time import sleep
from typing import List, Set, Tuple, Dict, Generator, TextIO

from loguru import logger
from pwn import process  # pwntools library

from topography import ONOS_TopologyGraph
import Utils
from MutatorManager import MutatorManager
from data_structure.LLDP import TLV


# 一些文件路径配置
log_path: str = 'logs/'
scenario_path: str = 'scenarios/onos/'
trigger_packet_file = 'trigger_packet.txt'
will_draw = False  # 是否绘制拓扑图

# 一些常量
http_proxy: str = ''
os_username: str = 'ylc'
malicious_host: str = ''
delimited_length: Dict = {'onos_1': 90,'floodlight': 160, 'opendaylight': 180,'onos_2': 290}  # 根据长度判断是否是哪个控制器的哪种 LLDP 包（ONOS有两个）, 90(84), 160(150), 290(278), 180(170) 分别区分
tlv_start_index: int = 14    # TLV 开始的索引值
swarm_extra_init_times: int = 5 - 3  # 总次数减种群遍历数=额外次数
fuzz_scenario_times: int = 15    # 模糊测试场景次数
fuzz_lldp_times: int = 50    # 模糊测试场景内单个 LLDP 包次数
get_latency: str = 'h1 ping -c 3 h5'
original_stdout: TextIO

# 需要用到的全局变量
onos: process
mininet: process    # 因为涉及到外部链路，pingall 的时候需要等很久（ping不通），因此尽可能一次性多用 mininet，减少开销
clusterMetadata_name: str = ''
secret: str = ''
mode_times: int = 0    # 模糊重复测试场景次数，由用户输入

onos_scenarios: list[list[str]]
lldp_scenarios: list[list[str]]
mix_scenarios: list[list[str]]
mutator_manager: MutatorManager
old_topography: ONOS_TopologyGraph.ONOSTopologyGraph
mutated_topography: List[ONOS_TopologyGraph.ONOSTopologyGraph] = []  # 设置为集合的话，会出现不可哈希的问题，会导致无法判断是否出现过
chosen_scenario_index: int = -1

send_packets = 0
massages: Dict = {}
is_eval:bool = False
score: Dict = {}
env_constraint_enable: bool = True
oracle_times:Dict = {'error':0, 'topology':0, 'latency':0}


def read_scenarios_file(src_mac: str, scenario_file_path: str):
    global scenario_path

    scenarios: List[List[str]] = []
    for filename in os.listdir(scenario_path + scenario_file_path):
        with open(scenario_path + scenario_file_path + filename, 'r') as f:
            lldp_list: List[str] = []
            while True:
                line = f.readline()
                if line == '':
                    break
                lldp_list.append(line[:12] + src_mac + line[24:])
            scenarios.append(lldp_list)
    return scenarios


def make_mix_scenarios(onos_scenarios_0: List[List[str]], lldp_scenarios_1: List[List[str]]) -> List[List[str]]:
    new_scenarios: List[List[str]] = []

    for index in range(max(len(onos_scenarios_0), len(lldp_scenarios_1))):
        onos_scenarios_index = random.randint(0, len(onos_scenarios_0) - 1)
        lldp_scenarios_index = random.randint(0, len(lldp_scenarios_1) - 1)
        combined_scenario = onos_scenarios_0[onos_scenarios_index] + lldp_scenarios_1[lldp_scenarios_index]
        random.shuffle(combined_scenario)
        new_scenarios.append(combined_scenario[:random.randint(1, len(combined_scenario))])
    return new_scenarios


def read_scenarios():
    """
    读取场景文件，顺便把所有的源MAC给改了
    :return: onos_scenarios, lldp_scenarios, mix_scenarios
    """

    src_mac = Utils.fingerprint_mac(clusterMetadata_name)
    scenarios_0 = read_scenarios_file(src_mac, 'onos_lldp/')
    scenarios_1 = read_scenarios_file(src_mac, 'lldp/')
    scenarios_2 = make_mix_scenarios(scenarios_0, scenarios_1)  # 利用已有的 ONOS 和 LLDP 场景生成多混合场景
    return scenarios_0, scenarios_1, scenarios_2


def lldp_data_capture(mininet_subprocess) -> Dict:
    global malicious_host

    # mininet_subprocess.interactive()
    mininet_subprocess.sendline(f'{malicious_host} sudo python tools/Capture_ONOS_LLDP_Data.py'.encode())
    # b'{"src_mac": "02eb4db5328e", "sig": "fe0ca423050400000193539e87d2fe24a4230505e3d2d34b527f079512a97a3b1ac757f767112a450b35e810444eac956c2a10b9"}\r\n'
    temp = mininet_subprocess.recvregex(b'{.*}').decode()
    lldp_data: Dict = json.loads(re.search(r'\{.*?}', temp).group().strip())
    return lldp_data


def identify_onos_lldp(lldp: bytearray) -> Dict:
    global tlv_start_index

    dst_mac: bytearray = lldp[:6]
    src_mac: bytearray = lldp[6:12]
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
        "src_mac": src_mac,
        "ether_type": ether_type,
        "tlvs": tlvs
    }
    return tmp_dict


def fill_tlv(new_lldp: bytearray, original_onos_lldp_data: Dict, tlv_type: Set[int],
             port_id: bytes, device_id: bytes, timestamp: bytes):
    """如果没有指定创建 Sig 的 TLV，填补对应必要的tlv."""
    if 2 not in tlv_type:   # PortID TLV
        new_lldp += original_onos_lldp_data['tlvs'][1].build_tlv()
        tlv_type.add(original_onos_lldp_data['tlvs'][1].get_type())
        port_id = original_onos_lldp_data['tlvs'][1].info.tobytes()[1:2]    # 直接访问 bytes 的下标是 int 型存储的，使用切片获取 bytes
    if 100 + 2 not in tlv_type:    # Device TLV
        new_lldp += original_onos_lldp_data['tlvs'][4].build_tlv()
        tlv_type.add(original_onos_lldp_data['tlvs'][4].get_type())
        device_id = original_onos_lldp_data['tlvs'][4].info.tobytes()
    if 100 + 4 not in tlv_type:   # TimeStamp TLV
        tmp_tlv = original_onos_lldp_data['tlvs'][5]
        timestamp = int(time.time() * 1000).to_bytes(8, 'big')
        tmp_tlv.update_information(timestamp)

        new_lldp += tmp_tlv.build_tlv()
        tlv_type.add(tmp_tlv.get_type())
        del tmp_tlv
    return port_id, device_id, timestamp


def update_onos_lldp(lldp_data: Dict, original_onos_lldp_data: Dict):
    # 更新 TimeStamp TLV 和 Sig TLV
    port_id: bytes = b'0'
    device_id: bytes = b''  # 实际device_id和port_id在验证签名的时候，没有指定的TLV type的话，onos就直接返回False了
    timestamp: bytes = b''


    tlv_type: Set[int] = set()  # 用于记录已经添加的 TLV 类型

    new_lldp: bytearray = lldp_data['dst_mac'] + lldp_data['src_mac'] + lldp_data['ether_type']

    for tlv in lldp_data['tlvs']:
        tlv_type.add(tlv.get_type())

    # 更新 TimeStamp and Sig TLV
    for tlv in lldp_data['tlvs']:
        if tlv.get_type() == 2:     # PortID TLV
            port_id = tlv.info.tobytes()[1:2]   # 直接访问 bytes 的下标是 int 型存储的，使用切片获取 bytes
        elif tlv.get_type() == 100 + 2:   # Device TLV
            device_id = tlv.info.tobytes()
        elif tlv.get_type() == 100 + 4:   # TimeStamp TLV
            timestamp = int(time.time() * 1000).to_bytes(8, 'big')
            tlv.update_information(timestamp)
        elif tlv.get_type() == 100 + 5:     # Sig TLV
            port_id, device_id, timestamp = fill_tlv(new_lldp, original_onos_lldp_data, tlv_type,
                                                     port_id, device_id, timestamp)

            tlv.update_information(Utils.creat_onos_sig(device_id, port_id, timestamp, secret))

        if tlv.get_type() != 0:  # 最后再添加结束 TLV
            new_lldp += tlv.build_tlv()
            tlv_type.add(tlv.get_type())

    if 100 + 5 not in tlv_type:     # Sig TLV没有，需要重新检查必要TLV，并添加 Sig TLV
        port_id, device_id, timestamp = fill_tlv(new_lldp, original_onos_lldp_data, tlv_type,
                                                 port_id, device_id, timestamp)

        tmp_tlv = original_onos_lldp_data['tlvs'][6]
        tmp_tlv.update_information(Utils.creat_onos_sig(device_id, port_id, timestamp, secret))

        new_lldp += tmp_tlv.build_tlv()
        tlv_type.add(tmp_tlv.get_type())
        del tmp_tlv

    new_lldp += b'\x00\x00'  # 结束 TLV
    return new_lldp


def send_mutated_lldp(new_onos_lldp: bytes, original_onos_lldp: str):
    global malicious_host, delimited_length, mininet, send_packets, env_constraint_enable

    if len(new_onos_lldp) < delimited_length['onos_1'] or env_constraint_enable is False:     # 普通 LLDP 包，或者没开启环境修补
        mininet.sendline(f'{malicious_host} sudo python tools/SendPacket.py {new_onos_lldp.hex()}'.encode())
    else:   # ONOS 的 LLDP 包会进行修补
        lldp_data:Dict = identify_onos_lldp(bytearray.fromhex(new_onos_lldp.hex()))
        original_onos_data = identify_onos_lldp(bytearray.fromhex(original_onos_lldp))
        new_onos_lldp = update_onos_lldp(lldp_data, original_onos_data)

        mininet.sendline(f'{malicious_host} sudo python tools/SendPacket.py {new_onos_lldp.hex()}'.encode())
    send_packets += 1
    logger.debug(f'Send packet: {new_onos_lldp}')
    return new_onos_lldp


def is_appeared(new_topography: ONOS_TopologyGraph.ONOSTopologyGraph) -> bool:
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
                 llpd_scenario: List[str], chosen_lldp_packet_index: int):
    global old_topography, onos, chosen_scenario_index, will_draw, massages, is_eval, oracle_times
    flag = 0

    # 接收 ONOS 可能出现的 ERROR log
    onos_data = onos.recvrepeat(0.5)  # 等待 ONOS 返回的反馋信息

    if onos.poll() is not None:
        logger.warning("Interesting, ONOS has exited.")

        atexit.unregister(Utils.close_onos)
        Utils.close_onos(onos)
        onos = init_onos(mininet)[0]
        atexit.register(Utils.close_onos, onos)

        flag = 1

    out = onos_data.decode()
    for line in out.splitlines():
        catches = re.match(r'^[^|]*\|\s*(.*?)\s*\|\s*.*?\s*\|\s*(.*?)\s*\|\s*[^|]*\|\s*(.*)$', line)
        if catches is None: # 未匹配到
            continue
        else:
            problem = re.sub(r'\d{6,}', '', catches.group(3))  # 具体问题，同时去除时间戳这种随机数字
            hash_code = hashlib.sha1(problem.encode()).hexdigest()
        if 'ERROR' in catches.group(1) and massages.get(hash_code, 0) < 5:  # 避开后者太常见了
            logger.warning("ONOS find error:\n{}", out)
            flag = 1
            if massages.get(hash_code, 0) == 0: # 可能没有该键
                massages[hash_code] = 1
            else:
                massages[hash_code] += 1
        elif 'WARN' in catches.group(1) and massages.get(hash_code, 0) < 5:  # 不对 Warn 反馈
            logger.warning("ONOS find warn:\n{}", out)
            if massages.get(hash_code, 0) == 0:
                massages[hash_code] = 1     # 可能有 'LLDP Packet failed to validate!', 可以后续看修补有效性
            else:
                massages[hash_code] += 1


    # 本可不需要，直接 elif 就行了，但是现在程序还是覆盖 bug 不全，所以需要这个来判断是否需要继续
    new_topography = ONOS_TopologyGraph.ONOSTopologyGraph()
    ONOS_TopologyGraph.build_topology_graph(new_topography)

    # 测试拓扑图一致性
    if old_topography.compare_topologies(new_topography) is False:
        # 判断是否曾经出现过相同的变异拓扑图
        if is_appeared(new_topography):    # 不能用 in，in 是比较的 networkx 的内存地址，要修改
            logger.debug("Same topology. May be Interesting. the LLDP packet is:\n {}", lldp_hex)
        else:
            flag = 2

        old_topography = new_topography

    if flag == 1:
        logger.warning("Interesting! onos raise something. The LLDP packet is:\n {}", lldp_hex)
        oracle_times['error'] += 1
    elif flag == 2:
        logger.warning("Interesting! Topological inconsistency. The LLDP packet is:\n {}", lldp_hex)
        oracle_times['topology'] += 1
    else:   # 最后测试链路状态
        temp = 0
        while temp < 2:
            mininet.sendline(get_latency.encode())
            per_recv = re.search(r'(\d+)% packet loss, time (\d+)ms',
                                 mininet.recvregex(rb"\d+% packet loss, time \d+ms").decode())
            if per_recv is None:
                flag = 3    # 直接就是断链路
                oracle_times['latency'] += 1
                break
            elif int(per_recv.group(1)) >= 75 or int(per_recv.group(2)) >= 17000: # 丢包率和时延
                temp += 1
                sleep(0.5)
            else:
                break

        if temp >= 2:
            flag = 3
            logger.warning("Interesting! High network link latency. The LLDP packet is:\n {}", lldp_hex)
            oracle_times['latency'] += 1
        del temp


    if flag > 0:
        if will_draw:
            # 图形化看看哪里不同
            new_topography.display_topology()

        mutated_topography.append(new_topography)

        mutator_manager.operators_eff[chosen_swarm][operator_enum][1] += 1  # 记录有效变异
        # TODO: 是否需要写回文件作为新的种子文件？

        # 有效变异包添加回场景，用于下次变异——种子回馈
        tmp_scenario = copy.deepcopy(llpd_scenario)
        tmp_scenario[chosen_lldp_packet_index] = lldp_hex

        if chosen_scenario_index == 0:
            onos_scenarios.append(tmp_scenario)
        elif chosen_scenario_index == 1:
            lldp_scenarios.append(tmp_scenario)
        elif chosen_scenario_index == 2:
            mix_scenarios.append(tmp_scenario)
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

    return mutator_manager.swarm_fuzz(chosen_swarm, chosen_lldp_packet) # lldp_mutation_iteration_max = 17


def fuzz_scenario(lldp_scenario: List[str], init_swarm_generator: Generator):

    for ___ in range(fuzz_lldp_times):  # 模糊测试场景内 LLDP 包次数
        chosen_lldp_packet_index: int = random.choice(range(len(lldp_scenario)))  # TODO: 概率选择场景中的一个 LLDP 包

        try:
            new_lldp_fuzz_data = mutate_lldp_packet(lldp_scenario[chosen_lldp_packet_index].strip(), init_swarm_generator)
            for i in range(len(new_lldp_fuzz_data[0])):
                try:
                    new_lldp_fuzz_data[0][i] = send_mutated_lldp(new_lldp_fuzz_data[0][i], lldp_scenario[chosen_lldp_packet_index].strip())
                    sleep(1.2)  # 等待一段时间，等待反馈信息，这个数字很影响整体系统的速度
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


def init_onos(mininet_subprocess: process = None):
    """
    初始化 ONOS 和 Mininet(如果没有的话)，并且获取 ONOS 的一些密钥数据.
    :param mininet_subprocess:
    :return: onos, mininet
    """
    global is_eval, os_username, http_proxy, clusterMetadata_name, secret


    # 启动 ONOS
    onos_subprocess = Utils.start_onos(os_username, http_proxy, is_eval)
    atexit.register(Utils.close_onos, onos_subprocess)

    if mininet_subprocess is None:
        # Mininet 网络拓扑初始化
        mininet_subprocess = Utils.start_mininet(1)
        atexit.register(Utils.close_mininet, mininet_subprocess)

    # 获取 ONOS 的一些密钥数据，此时 ONOS 会发送几个 LLDP 包，可以初始一下我们的拓扑图数据结构，让一些单向的交换机链路变成双向的
    packet_json = Utils.lldp_data_capture(mininet_subprocess, malicious_host)
    clusterMetadata_name, secret = Utils.find_Name_and_Secret(packet_json['SrcMac'], packet_json['DeviceId'],
                                                              packet_json['PortId'], packet_json['TimeStamp'],
                                                              packet_json['Sig'])

    return onos_subprocess, mininet_subprocess


def start_fuzzing(config: Dict, stdout: TextIO, eval_mode: bool):
    """
    开始 ONOS 模糊测试.
    :param stdout:
    :param config:
    :param eval_mode:
    :return:
    """
    global onos, mininet, clusterMetadata_name, secret, mode_times, swarm_extra_init_times, fuzz_scenario_times,\
        fuzz_lldp_times, os_username, http_proxy, malicious_host, delimited_length, tlv_start_index, mutated_topography,\
        old_topography, mutator_manager, onos_scenarios, lldp_scenarios, mix_scenarios, chosen_scenario_index, original_stdout,\
        get_latency, will_draw, is_eval, score, env_constraint_enable

    # 获取参数，如果没有传入则使用原本全局的值
    http_proxy = config['http_proxy']
    malicious_host = config['malicious_host']
    os_username = config['os_username']
    delimited_length = config['delimited_length']
    tlv_start_index = config['tlv_start_index']
    swarm_extra_init_times = config['swarm_extra_init_times']
    fuzz_scenario_times = config['fuzz_scenario_times']
    fuzz_lldp_times = config['fuzz_lldp_times']
    will_draw = config['will_draw']
    env_constraint_enable = config['env_constraint_enable']
    get_latency = config['get_latency_cmd']


    original_stdout = stdout
    is_eval = eval_mode
    # secret = secret
    # mutated_topography = mutated_topography
    # chosen_scenario_index = chosen_scenario_index
    # clusterMetadata_name = clusterMetadata_name


    # 检查代理是否可用
    if Utils.check_proxy(http_proxy.split(':')[1].split('//')[1], int(http_proxy.split(':')[2])) is False:
        logger.error("Proxy is not available.")
        sys.exit(1)

    # 用户输入模糊测试场景次数
    try:
        logger.info("Please input the mode fuzzing times:")
        mode_times = int(input())    # 这里实际上被替换成了 pwn 库中的 readline() 函数，暂时不知道怎么解决
    except ValueError:
        logger.error("Invalid input.")
        sys.exit(1)

    logger.info("TSFuzzer started.")

    onos, mininet = init_onos()

    logger.debug("ONOS and Mininet started. Message: {}", onos.recvrepeat(timeout=0.8).decode())    # recvall() 会一直等待，直到超时（会强制退出onos，但是onos的服务不会退出）

    # 读取场景文件
    onos_scenarios, lldp_scenarios, mix_scenarios = read_scenarios()
    logger.info("Scenarios loaded.")
    logger.trace("ONOS scenarios: {}", onos_scenarios)
    logger.trace("LLDP scenarios: {}", lldp_scenarios)

    # 后续需要使用的一些变量或者对象
    mutator_manager = MutatorManager(mininet, malicious_host, delimited_length, config['lldp_mutation_iteration_max'])
    init_swarm_generator = mutator_manager.select_swarm_init(swarm_extra_init_times)


    # 初始化拓扑图数据结构
    old_topography = ONOS_TopologyGraph.ONOSTopologyGraph()
    ONOS_TopologyGraph.build_topology_graph(old_topography)
    if will_draw:
        old_topography.display_topology()
    mutated_topography.append(old_topography)
    logger.info("Initial topology graph has been built.")

    if is_eval is True:
        # 先清理之前的覆盖率数据
        Utils.clear_old_coverage_data("evaluation/onos-coverage.exec", "evaluation/onos-coverage.json")
        logger.info("Old coverage data cleared.")
        # 首次保存未 Fuzzing 的覆盖率数据
        Utils.save_coverage_score("ONOS", config['onos_root'], "evaluation/jacoco/lib/jacococli.jar",
                                  "evaluation/onos-coverage.exec",
                                  "evaluation/onos-report.xml", "evaluation/onos-coverage.json", )

    for _ in range(mode_times):  # 模式测试次数

        # 选择一个模式
        chosen_scenario_index = random.choice([0, 1, 2])  # 0: ONOS, 1: LLDP, 2: MIX
        # chosen_scenario_index = 0  # 测试

        for __ in range(fuzz_scenario_times):  # 测试场景
            logger.info('\n\n' + '-' * 100 + '\n')

            if chosen_scenario_index == 0:
                logger.info("Fuzzing ONOS LLDP scenario.")
                chosen_onos_scenario = random.choice(onos_scenarios)  # TODO: 是否需要概率选择？
                logger.info('Chosen onos scenario index: {}', onos_scenarios.index(chosen_onos_scenario))
                fuzz_scenario(chosen_onos_scenario, init_swarm_generator)
            elif chosen_scenario_index == 1:
                logger.info("Fuzzing LLDP scenario.")
                chosen_lldp_scenario = random.choice(lldp_scenarios)  # TODO: 是否需要概率选择？
                logger.info('Chosen lldp scenario index: {}', lldp_scenarios.index(chosen_lldp_scenario))
                fuzz_scenario(chosen_lldp_scenario, init_swarm_generator)
            elif chosen_scenario_index == 2:
                logger.info("Fuzzing mixed scenario.")
                chosen_mix_scenario = random.choice(mix_scenarios)
                logger.info('Chosen mix scenario index: {}', mix_scenarios.index(chosen_mix_scenario))
                fuzz_scenario(chosen_mix_scenario, init_swarm_generator)

            # 重启 mininet
            atexit.unregister(Utils.close_mininet)
            Utils.close_mininet(mininet)
            mininet = Utils.start_mininet(1)
            atexit.register(Utils.close_mininet, mininet)
            logger.debug("ONOS and Mininet started. Message: {}", onos.recvrepeat(0.8).decode())

            mutator_manager.mininet_subprocess = mininet
            old_topography.graph.clear()
            ONOS_TopologyGraph.build_topology_graph(old_topography)  # 重启 mininet 后，需要重新构建拓扑图

            if is_eval is True:
                Utils.save_coverage_score("ONOS", config['onos_root'], "evaluation/jacoco/lib/jacococli.jar",
                                     "evaluation/onos-coverage.exec",
                                     "evaluation/onos-report.xml", "evaluation/onos-coverage.json",)

        # 重启 onos
        atexit.unregister(Utils.close_onos)
        Utils.close_onos(onos)
        onos = init_onos(mininet)[0]
        atexit.register(Utils.close_onos, onos)

    logger.info(f"All Send times: {send_packets}")
    logger.info(f'Oracle times: {oracle_times}')