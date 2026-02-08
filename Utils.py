import binascii
import datetime
import hashlib
import hmac
import os  # os 是操作系统的，sys库是操作本python环境的
import signal
import socket
import sys
import threading
import json
import re
import concurrent.futures
import xml.etree.ElementTree as ET
from concurrent.futures._base import Future
from typing import Optional, Union, Dict

import mmh3
import psutil
import requests
from loguru import logger
from pwn import process, STDOUT
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3 import Retry

from data_structure import ONOS_TopologyComponent, FLT_TopologyComponent

running_log_path = ''

# 设置ONOS的主机名和端口
onos_host = '127.0.0.1'  # 替换为实际的 ONOS 主机名或 IP 地址
onos_port = '8181'

floodlight_host = '127.0.0.1'
floodlight_port = '8080'

odl_host = '127.0.0.1'
odl_port = '8181'

# 设置用户名和密码
onos_username = 'onos'
onos_password = 'rocks'

odl_username = 'admin'
odl_password = 'admin'

java_home = '/usr/lib/jvm/java-17-openjdk-amd64/'

# 获取拓扑的URL
onos_switches_url = f'http://{onos_host}:{onos_port}/onos/v1/devices'
onos_links_url = f'http://{onos_host}:{onos_port}/onos/v1/links'
onos_hosts_url = f'http://{onos_host}:{onos_port}/onos/v1/hosts'

floodlight_switches_url = f'http://{floodlight_host}:{floodlight_port}/wm/core/controller/switches/json'
floodlight_hosts_url = f'http://{floodlight_host}:{floodlight_port}/wm/device/'
floodlight_links_url = f'http://{floodlight_host}:{floodlight_port}/wm/topology/links/json'

odl_topology_url = f'http://{odl_host}:{odl_port}/rests/data/network-topology:network-topology?content=nonconfig'

# 用于终止floodlight进程的事件
stop_event = threading.Event()
executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)


def add_logger(log_path: str, output_terminal=sys.stdout):
    global running_log_path
    if running_log_path == '':  # 防止多次调用该函数产生很多文件
        running_log_path = log_path + f'{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.log'

    # 运行输出 log
    logger.add(output_terminal, level="DEBUG", colorize=True,
               format="<green>{time}</green> | <blue>{module}</blue> | <level>{level}</level> | <d><c>{message}</c></d>")
    # 记录 log
    logger.add(running_log_path,
               level="DEBUG", colorize=True, rotation='500 MB', retention='15 days')
    # 有效测试 log
    logger.add(log_path + 'interesting.log', level="INFO", colorize=True, rotation='300 MB', backtrace=True,
               enqueue=True,  # 记录完整异常, 支持多线程写入
               filter=lambda record: "Interesting" in record["message"] or 'ERROR' in record[
                   'message'] or 'Difference' in record['message'])  # 对指定 log 信息特殊处理
    # 错误 log
    logger.add(log_path + 'error.log', level="ERROR", colorize=True, rotation='300 MB', backtrace=True,
               enqueue=True)  # 记录完整异常, 支持多线程写

def check_proxy(host: str, port: int) -> bool:
    """
    Check if the proxy server port is open.

    :param host: Proxy server host
    :param port: Proxy server port
    :return: True if the port is open, False otherwise
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)  # Set a timeout for the connection attempt
        try:
            sock.connect((host, port))
            return True
        except (socket.timeout, socket.error):
            return False


def terminate_descendants(parent_pid):
    """终止一个进程不会默认终止其子进程，这里手动终止."""
    parent = psutil.Process(parent_pid)
    for child in parent.children(recursive=True):  # 递归查找子孙进程
        try:
            child.terminate()  # 发送 SIGTERM
            # os.kill(child.pid, signal.SIGINT)
            child.wait()  # 等待子进程终止
            logger.debug(f"Terminate sub-process PID: {child.pid}")

        except psutil.NoSuchProcess:
            logger.debug(f"Parent PID {parent_pid} does not exist or has exited.")
        except Exception as e:
            logger.debug(f"An error occurred while terminating the child process. {e}")


def read_floodlight_before_start_mininet(controller: process):
    """不及时读取的话，floodlight输出缓冲满了就阻塞了，会导致mininet ping不通."""
    global stop_event

    while not stop_event.is_set():
        data = controller.recv(timeout=0.4)
        if not data:
            continue
        logger.debug(f'process: {data.decode().strip()}')


def start_onos(tsf_username: str, http_proxy: str, is_eval: bool) -> process:
    """
    另开一个 bash shell 去启动 ONOS.

    只有这种解决方法好用，不然其他的系统 API 都是新建一个 shell，只有一次性调用一个 shell 去执行全部命令才能实现.
    :param is_eval:
    :param tsf_username:
    :param http_proxy:
    :return:
    """

    # Set the http_proxy environment variable
    project_path = os.getcwd()

    # Create a shell script to source the bash profile and start ONOS, auto activate the fwd app
    onos = process(['sudo', '-iu', tsf_username])  # 进入 tsf 用户的 shell 和环境
    """
    另开 shell 一则有利于不影响后续操作，
    二则可以发送命令去执行shell内置命令——正常情况无法使用python的pwn.process()等函数执行shell内置命令(每次命令都是找PATH执行的)。
    """

    onos.sendline(f'export http_proxy={http_proxy}'.encode())
    onos.sendline(
        b'export JAVA_DEBUG_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=\*:5005')  # 开启远程调试
    if is_eval:
        # 因为base_dir路径指向是文件而不是目录，只能使用 os 函数，无法使用 ../
        onos.sendline(
            f'export JAVA_OPTS=-javaagent:{os.path.dirname(os.path.abspath(__file__))}/evaluation/jacoco/lib/jacocoagent.jar=output=tcpserver,address=*,port=6300,'
            f'includes=org.onosproject.net.topology.*:org.onosproject.net.link.*:org.onlab.packet.*:org.onlab.graph.*:org.onosproject.net.host.*:'
            f'org.onosproject.net.device.*:org.onosproject.ui.model.topo.*:org.onosproject.app.*:org.onosproject.net.driver.*:org.onosproject.store.*:'
            f'org.onosproject.event.*:org.onosproject.net.flow.*:org.onosproject.net.resource.*'.encode()) # onos 的 shell 脚本会读取此环境变量接到 java 命令行参数中
    onos.sendline(f'source {project_path}/tools/run_onos.sh'.encode())  # 如果不预先编译一次 onos 的话，这里会等很久，可能会报错

    # onos.recvuntil(b'state to READY')  # Wait for ONOS to start
    onos.recvrepeat(2)
    logger.info("ONOS started.")
    return onos


def close_onos(onos: process):
    """
    关闭 ONOS.
    :param onos:
    :return:
    """
    if onos.poll() is None:
        terminate_descendants(onos.pid)  # onos 指向的其实是 bash shell，所以要终止子进程
        os.kill(onos.pid, signal.SIGINT)  # kill 会执行 onos 的清理动作，类似 signal.SIGINT
        # onos.kill() # kill 不会执行 onos 的清理动作，只是强制关闭，类似 signal.KILL

        # 余下的几个单独的进程，不知道是什么，并且后面那个不需要加 "" ，process会自动处理的，只有在shell模式下才需要加 ""
        process(['pkill', '-f', 'bazel(onos)*'])
        process(['pkill', '-f', '/tmp/onos-*-jdk/bin*'])

    logger.info("ONOS closed.")


def start_floodlight(tsf_username: str, is_eval: bool) -> process:
    """
    启动 Floodlight.
    :param is_eval:
    :param tsf_username:
    :return:
    """

    project_path = os.getcwd()

    floodlight = process(['sudo', '-iu', tsf_username])  # 进入 tsf 用户的 shell 和环境
    # floodlight.sendline(b'export JAVA_DEBUG_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=\*:5005')  # 开启远程调试
    if is_eval:
        floodlight.sendline(
            f'export JAVA_OPTS=-javaagent:{os.path.dirname(os.path.abspath(__file__))}/evaluation/jacoco/lib/jacocoagent.jar=output=tcpserver,address=*,port=6300,'
            f'includes=net.floodlightcontroller.linkdiscovery.*:net.floodlightcontroller.topology.*:net.floodlightcontroller.routing.*:net.floodlightcontroller.forwarding.*'.encode()) # floodlight 需要后续手动添加 java 参数
    floodlight.sendline(f'source {project_path}/tools/run_floodlight.sh'.encode())

    floodlight.recvuntil(b'Starting DebugServer on')  # Wait for Floodlight to start
    logger.info("Floodlight started.")

    return floodlight


def close_floodlight(floodlight: process):
    """
    关闭 Floodlight.
    :param floodlight:
    :return:
    """
    if floodlight.poll() is None:
        terminate_descendants(floodlight.pid)
        floodlight.kill()

    logger.info("Floodlight closed.")


def start_opendaylight(tsf_username: str) -> process:
    """
    启动 OpenDayLight.
    :param tsf_username:
    :return:
    """

    project_path = os.getcwd()

    odl = process(['sudo', '-iu', tsf_username])  # 进入 tsf 用户的 shell 和环境
    # odl.sendline(b'export JAVA_DEBUG_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=\*:5005')  # 开启远程调试
    odl.sendline(f'export JAVA_HOME={java_home}'.encode())
    odl.sendline(f'source {project_path}/tools/run_odl.sh'.encode())  # 需要在指定文件中预先添加自启动的feature

    # 等待启动的odl高亮提示符比特字符串
    odl.recvuntil(bytes.fromhex('1b5b33366d6f70656e6461796c696768742d757365721b5b33393b316d401b5b33343b32326d726f6f741b5b306d3e'))  # Wait for odl to start
    logger.info("OpenDayLight started.")

    return odl


def close_opendaylight(odl: process):
    """
    关闭 OpenDatLight.
    :param odl:
    :return:
    """
    if odl.poll() is None:
        terminate_descendants(odl.pid)
        odl.kill()

    logger.info("OpenDayLight closed.")


def start_mininet(controller_type: int, controller: process = None) -> process:
    """
    启动 Mininet 拓扑.

    :param controller_type: 控制器类型. 1: ONOS, 2: Floodlight, 3: OpenDayLight
    :param controller: 控制器进程对象.
    :return: Mininet 进程对象.
    """
    global stop_event
    read_floodlight: Optional[threading.Thread, Future] = None

    stop_event.clear()

    # 预先清除一下 Mininet 拓扑
    mininet_close = process(['sudo', 'mn', '-c'], stderr=STDOUT)
    mininet_close.recvrepeat(0.5)
    if mininet_close.poll() is None:
        mininet_close.kill()
        mininet_close.close()

    # noinspection SpellCheckingInspection
    mininet_process = process(
        ['sudo', 'mn', '--custom', 'topologies/mix_topo.py', '--topo', 'mytopo', '--controller', 'remote'])

    try:
        mininet_process.recvuntil(b"Starting CLI:")
    except EOFError:  # 有时候会存在文件残留，导致第一次启动是清理动作
        mininet_process.wait()  # 等待 mininet 进程正常结束
        # noinspection SpellCheckingInspection
        mininet_process = process(
            ['sudo', 'mn', '--custom', 'topologies/mix_topo.py', '--topo', 'mytopo', '--controller', 'remote'])
        mininet_process.recvuntil(b"Starting CLI:")

    if controller_type != 3:  # ODL 不需要 pingall, 因为没有对应组件 ping 不通
        if controller is not None:  # floodlight 必须要同步读取输出，否则会阻塞
            # read_floodlight = threading.Thread(target=read_floodlight_before_start_mininet, args=(controller,))
            # read_floodlight.start()
            # read_floodlight = executor.submit(read_floodlight_before_start_mininet, controller)
            data = controller.recvrepeat(1)
            if len(data) > 0:
                logger.debug(f'process: {data.decode().strip()}')

        mininet_process.sendline(b'pingall')
        mininet_process.recvuntil(b"Results:")

    stop_event.set()
    if read_floodlight is not None:
    #     read_floodlight.join()  # 确认线程 + context 已退出
        read_floodlight.result(timeout=2)

    logger.info("Mininet started.")
    # sleep(0.3)
    return mininet_process


def close_mininet(mininet_process: process):
    """
    关闭 Mininet 拓扑.
    :param mininet_process:
    :return:
    """
    if mininet_process.poll() is None:
        mininet_process.sendline(b'exit')
        mininet_process.wait(30)  # 等待 mininet 进程正常结束，有时候不能正常关闭，一直等待，很奇怪
        # mininet_process.recvall()   # 接受数据然后关闭进程,好像有时候不会接受到 EOF 符
        if mininet_process.poll() is None:
            mininet_process.kill()

    logger.info("Mininet closed.")


def get_switches(controller_type: str,
                 topology: Union[ONOS_TopologyComponent.Topology, FLT_TopologyComponent.Topology]):
    """获取交换机信息."""
    if controller_type == 'ONOS':
        response = requests.get(onos_switches_url, auth=HTTPBasicAuth(onos_username, onos_password))
    elif controller_type == 'Floodlight':
        response = requests.get(floodlight_switches_url)
    else:
        raise ValueError("Invalid controller type.")

    if response.status_code == 200:
        topology.load_from_response(1, response.json())
        return True
    else:
        print("Failed to fetch devices:", response.status_code, response.text)
        return None


def request_with_retry(url: str, auth=None, retries=3, timeout=5) -> requests.Response:
    """
    发送带有重试机制和超时的 HTTP GET 请求.
    配置了3次重试，每次间隔0.5秒，如果最终仍超时或失败，将抛出异常供上层捕获.
    """
    session = requests.Session()
    # 以此配置重试策略：总共重试3次，针对500/502/503/504错误码，退避因子0.5秒
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        method_whitelist=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # 发起请求，强制设置超时时间（连接超时+读取超时）
    response = session.get(url, auth=auth, timeout=timeout)
    return response


def get_links(controller_type: str, topology: Union[ONOS_TopologyComponent.Topology, FLT_TopologyComponent.Topology]):
    """获取链路信息."""
    if controller_type == 'ONOS':
        response = requests.get(onos_links_url, auth=HTTPBasicAuth(onos_username, onos_password))
    elif controller_type == 'Floodlight':
        # response = requests.get(floodlight_links_url)
        response = request_with_retry(floodlight_links_url)  # Floodlight 有问题，必须使用这种重试机制和异常机制
    else:
        raise ValueError("Invalid controller type.")

    if response.status_code == 200:
        topology.load_from_response(2, response.json())
        return True
    else:
        print("Failed to fetch links:", response.status_code, response.text)
        return None


def get_hosts(controller_type: str, topology: Union[ONOS_TopologyComponent.Topology, FLT_TopologyComponent.Topology]):
    """获取主机信息."""
    if controller_type == 'ONOS':
        response = requests.get(onos_hosts_url, auth=HTTPBasicAuth(onos_username, onos_password))
    elif controller_type == 'Floodlight':
        response = requests.get(floodlight_hosts_url)
    else:
        raise ValueError("Invalid controller type.")

    if response.status_code == 200:
        topology.load_from_response(3, response.json())
        return True
    else:
        print("Failed to fetch topology:", response.status_code, response.text)
        return None


def get_topology(controller_type: str,
                 topology: Union[ONOS_TopologyComponent.Topology, FLT_TopologyComponent.Topology] = None) -> Optional[
    requests.Response]:
    """
    获取拓扑信息.

    :param controller_type:
    :param topology: 存入拓扑信息的对象.
    :return:
    """
    try:
        if controller_type == 'ODL':  # odl 只有一个 topology，不需要分开获取
            headers = {"content-type": "application/json"}
            auth = HTTPBasicAuth(odl_username, odl_password)
            response = requests.get(odl_topology_url, headers=headers, auth=auth)

            if response.status_code == 200:
                return response
            else:
                raise ConnectionError

        if get_switches(controller_type, topology) is False:
            print("Failed to fetch devices.")
        if get_links(controller_type, topology) is False:
            print("Failed to fetch links.")
        if get_hosts(controller_type, topology) is False:
            print("Failed to fetch hosts.")
    except Exception as e:
        logger.debug(f"Get topology data find Error: {e}")
        raise ConnectionError
    return None


def lldp_data_capture(mininet_subprocess: process, malicious_host: str) -> Dict:
    # mininet_subprocess.interactive()
    mininet_subprocess.sendline(f'{malicious_host} sudo python tools/Capture_ONOS_LLDP_Data.py'.encode())
    # b'{"src_mac": "02eb4db5328e", "sig": "fe0ca423050400000193539e87d2fe24a4230505e3d2d34b527f079512a97a3b1ac757f767112a450b35e810444eac956c2a10b9"}\r\n'
    temp = mininet_subprocess.recvregex(b'{.*}').decode()
    lldp_data: Dict = json.loads(re.search(r'\{.*?}', temp).group().strip())
    return lldp_data


def fingerprint_mac(ClusterMetadata_name: str) -> str:
    # 如果 ClusterMetadata 为空，则返回默认 MAC
    # if cm is None:
    #     return "02:eb:00:00:00:00"

    # 生成哈希值
    hash_value = mmh3.hash(ClusterMetadata_name.encode('utf-8'))

    # 将哈希结果转换为 MAC 地址格式，前缀为 02:eb
    mac_prefix = "02eb"
    mac_parts = [f"{(hash_value >> (i * 8)) & 0xFF:02x}" for i in range(4)]
    mac_address = f"{mac_prefix}{''.join(mac_parts)}"

    return mac_address


def find_Name_and_Secret(src_mac: str, deviceID: str, portNum: str, timeStamp: str, now_sig: str):
    """
    利用生成密钥的原理，穷举寻找密钥.
    :param src_mac:
    :param now_sig:
    :param deviceID:
    :param portNum:
    :param timeStamp:
    :return:
    """

    '''
    原理:
    ONOS启动好像会先运行onos/tools/dev/p4vm/start_onos.sh，密钥使用:
        cat {following_data} > $ONOS_DIR/config/cluster.json <<-EOF
    
        {
          "name": "default-$RANDOM",
          "node": {
            "id": "$IP",
            "ip": "$IP",
            "port": 9876
          },
          "clusterSecret": "$RANDOM"
        }
        
        EOF
    
    $RANDOM 是一个 Bash 内置变量，用于生成一个介于 0 和 32767 之间的伪随机数。
    
    '''
    name: str = ''
    secret: str = ''

    for i in range(32767 + 1):
        if secret == '' and bytes.fromhex(now_sig) == creat_onos_sig(bytes.fromhex(deviceID), bytes.fromhex(portNum),
                                                                     bytes.fromhex(timeStamp), str(i)):
            secret = str(i)
        if name == '' and fingerprint_mac(f"default-{i}") == src_mac:
            name = f"default-{i}"

    return name, secret


def creat_onos_sig(deviceID: bytes, portId: bytes, timestamp: bytes, secret: str):
    """
    HmacSHA256 加密算法.
    :param deviceID:
    :param portId:
    :param timestamp:
    :param secret:
    :return:
    """
    # 将 port_num 和 timestamp 转换为字节形式
    # 如果 bitarray 长度不足 64 位，则左边填充 0
    device_id = deviceID
    try:
        pnm = int(portId.decode()).to_bytes(8, byteorder='big')
    except ValueError:
        pnm = portId
    tsp = timestamp

    # 创建 HMAC-SHA256 签名密钥
    signing_key = secret.encode('utf-8')

    # 初始化 HMAC-SHA256
    mac = hmac.new(signing_key, digestmod=hashlib.sha256)

    # 更新 HMAC 内容
    mac.update(device_id)  # 添加设备ID
    mac.update(pnm)  # 添加端口号的字节
    mac.update(tsp)  # 添加时间戳的字节

    # 计算最终的 HMAC 并返回
    result = mac.digest()
    return result

def create_odl_sig(key: str, tp:bytes, ObjectToString: str = 'Uri{value=*}'):
    # "Uri{value=openflow:1:1}aa9251f8-c7c0-4322-b8d6-c3a84593bda3"
    real_input_str = ObjectToString.replace('*', tp.decode()) + key
    calc_bytes = hashlib.md5(real_input_str.encode('utf-8')).digest()
    return binascii.hexlify(calc_bytes).decode()

def get_jacoco_report(controller:str, classes_dir:str, jacoco_cli_file: str, exec_file_path:str, xml_file_path:str):
    """
    获取 Jacoco 报告. 需要以线程运行，提高效率.
    :param controller:
    :param classes_dir:
    :param jacoco_cli_file:
    :param exec_file_path:
    :param xml_file_path:
    :return:
    """
    # Dump命令，java -jar Jacoco/lib/jacococli.jar dump --address 127.0.0.1 --port 6300 --destfile tmp/onos-coverage.exec
    dump_cmd = [
        "java", "-jar", jacoco_cli_file, "dump",
        "--address", "127.0.0.1", "--port", "6300", "--destfile", exec_file_path
    ]

    if controller == 'ONOS':
        onos_root_dir = classes_dir  # 因为 process 是系统调用，会绕过 shell 执行程序——shell的bash_rc不会执行，因此需要手动获取路径
        # Report 命令，java -jar /home/avaritia/Project/TSF/Jacoco/lib/jacococli.jar report tmp/onos-coverage.exec --classfiles ~/Project/onos/bazel-bin/core/api/libonos-api.jar --classfiles ~/Project/onos/bazel-bin/utils/misc/libonlab-misc.jar --xml tmp/onos-report.xml
        report_cmd = [
            "java", "-jar", jacoco_cli_file, "report", exec_file_path,
            "--classfiles", f"{onos_root_dir}bazel-bin/core/api/libonos-api.jar",
            "--classfiles", f"{onos_root_dir}bazel-bin/utils/misc/libonlab-misc.jar",
            "--xml", xml_file_path
        ]
    elif controller == 'Floodlight':
        # floodlight 这个需要在新目录 classes_runtime 使用 jar xf 提取一下 jar 包，然后删除 javax目录（含多重同名依赖），这样 Jacoco 才能成功解析
        report_cmd = [
            "java", "-jar", jacoco_cli_file, "report", exec_file_path,
            "--classfiles", f"{classes_dir}net/floodlightcontroller/",  # floodlight 项目不大直接在 classfiles 指定目录让 Jacoco 自己搜索即可
            "--xml", xml_file_path
        ]
    else:
        raise ValueError ("Invalid controller type for Jacoco report.")
    try:
        p1 = process(dump_cmd)
        p1.wait_for_close()
        p1.close()

        p2 = process(report_cmd)
        p2.wait_for_close()
        p2.close()
    except Exception as e:
        print(f"[!] Coverage update failed: {e}")


def parse_score(xml_file) -> Optional[Dict[str, Dict[str, Union[int, float]]]]:
    """
    从 Jacoco XML 文件中提取分数.
    :param xml_file: XML 文件路径
    :return: 分数值
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # 1. 定义需要关注的拓扑相关包 (注意：JaCoCo XML中使用 '/' 而非 '.' 分隔)
        # 定义目标包（使用 . 作为通用匹配，代码里会自动处理）
        target_packages = [
            "org.onosproject.net.topology",
            "org.onosproject.net.link",
            "org.onlab.packet",
            "org.onlab.graph",
            # "org.onosproject.net.host",
            "org.onosproject.net.device",
            "org.onosproject.ui.model.topo",

            "org.onosproject.app",
            "org.onosproject.net.driver",
            "org.onosproject.store",
            "org.onosproject.event",
            "org.onosproject.net.flow",
            "org.onosproject.net.resource"
        ]

        metrics = {
            "INSTRUCTION": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0},     # 指令覆盖率
            "BRANCH": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0},   # 分支覆盖率
            "LINE": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0}, # 粗粒度，没有指令覆盖率精确
            "COMPLEXITY": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0},   # 圈复杂度
            "METHOD": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0},
            "CLASS": {"covered": 0, "missed": 0, "total": 0, "percent": 0.0}
        }

        # 2. 遍历所有 <package> 节点，而不是读取根节点的 <counter>
        for package in root.findall('package'):
            raw_name = package.get('name')  # 获取包名，例如 org/onosproject/net/topology/impl
            pkg_name = raw_name.replace('/', '.')

            # 3. 判断该包是否属于我们的目标范围
            is_target = False
            # for target in target_packages:
            #     # 使用 startswith 确保子包也被包含在内
            #     if pkg_name.startswith(target):
            #         is_target = True
            #         break

            if pkg_name in target_packages: # 尝试是否能够增加覆盖率计算值
                is_target = True

            # 4. 如果是目标包，累加其数据
            if is_target:
                for counter in package.findall('counter'):
                    c_type = counter.get("type")

                    if c_type in metrics:
                        covered = int(counter.get("covered"))
                        missed = int(counter.get("missed"))
                        total = covered + missed

                        # 注意：这里改为 += 累加，因为我们要把多个包的数据加起来
                        metrics[c_type]["covered"] += covered
                        metrics[c_type]["missed"] += missed
                        metrics[c_type]["total"] += total

        # 5. 最后统一计算百分比
        for key, data in metrics.items():
            if data["total"] > 0:
                data["percent"] = (data["covered"] / data["total"] * 100)
            else:
                data["percent"] = 0.0

        # # 会有一个全局汇总数据在后面，位于 report 根节点下，是整个报告的总和（包含包、类、方法三个级别的计数器）
        # for counter in root.findall('counter'):
        #     c_type = counter.get("type")
        #
        #     if c_type in metrics:
        #         covered = int(counter.get("covered"))
        #         missed = int(counter.get("missed"))
        #         total = covered + missed
        #
        #         metrics[c_type]["covered"] = covered
        #         metrics[c_type]["missed"] = missed
        #         metrics[c_type]["total"] = total
        #         metrics[c_type]["percent"] = (covered / total * 100) if total > 0 else 0.0

        return metrics
    except Exception as e:
        print(f"解析失败: {e}")
        return None

def save_coverage_score(controller:str, classes_path:str, jacoco_cli_file: str, exec_file_path:str, xml_file_path:str, save_path:str):
    get_jacoco_report(controller, classes_path, jacoco_cli_file, exec_file_path, xml_file_path)
    coverage_metrics = parse_score(xml_file_path)
    with open(save_path, 'a+', encoding='utf-8') as f:
        f.write(json.dumps(coverage_metrics) + '\n')


def clear_old_coverage_data(exec_file_path:str, json_file_path:str):
    """
    清理 Jacoco 覆盖率数据文件.
    :param exec_file_path:
    :param json_file_path:
    :return:
    """
    if os.path.exists(exec_file_path):
        os.remove(exec_file_path)
    if os.path.exists(json_file_path):
        os.remove(json_file_path)