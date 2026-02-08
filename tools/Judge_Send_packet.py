import hmac
import os
from time import sleep

from pwn import process, context
from scapy.all import *

sys.path.append("../") # 表示 Python 解释器在导入模块时搜索的目录路径，添加上级目录到 sys.path，使得可以引用上级目录的模块, 但是这样会导致 IDE 无法识别上级目录的模块，可以单独运行

print(os.getcwd()) # 这个是操作系统的当前工作目录，不是 Python 解释器的当前工作目录
from topography import FLT_TopologyGraph, ONOS_TopologyGraph, ODL_TopologyGraph
import Utils
os.chdir('../')


secret: str = ''
target: str = ''
module: str = ''
log_index: int
mininet: process
delimited_length: Dict = {'onos_1': 90,'floodlight': 160, 'opendaylight': 180,'onos_2': 290}  # 根据长度判断是否是哪个控制器的哪种 LLDP 包（ONOS有两个）, 90(84), 160(150), 290(278), 180(170) 分别区分


nice_avg_latency = -1  # 网络平均延迟稳定的动态标准
nice_max_latency = -1	# 网络最大延迟稳定的动态标准

context.log_level = 'debug'

def send_packet(lldp: str):
	global secret

	if delimited_length['opendaylight'] < len(lldp) < delimited_length['onos_2']:
		device_id:bytes = bytes.fromhex(lldp[114:152])
		timestamp = int(time.time() * 1000).to_bytes(8, 'big')
		tsp = timestamp
		# tsp = bytes.fromhex(lldp[164:180])

		try:
			pnm = int(bytes.fromhex(lldp[52:54]).decode()).to_bytes(8, byteorder='big')
		except ValueError:
			pnm = bytes.fromhex(lldp[52:54])

		# 创建 HMAC-SHA256 签名密钥
		signing_key = secret.strip().encode('utf-8')

		# 初始化 HMAC-SHA256
		mac = hmac.new(signing_key, digestmod=hashlib.sha256)
		mac.update(device_id)  # 添加设备ID
		mac.update(pnm)  # 添加端口号的字节
		mac.update(tsp)  # 添加时间戳的字节
		result = mac.digest()

		new_lldp = Raw(bytes.fromhex(lldp[:164]) + tsp + bytes.fromhex(lldp[180:192] + result.hex() + lldp[256:]))

	else:
		new_lldp = Raw(bytes.fromhex(lldp))

	sendp(new_lldp)


def judge_network_status(rtt_0, rtt_1, threshold_avg=10, threshold_max=15, alpha=0.3):
	"""差异阈值法判断网络延迟是否稳定"""
	global nice_avg_latency, nice_max_latency

	# 计算两次ping结果的差异
	diff_avg = abs(rtt_0[1] - rtt_1[1])  # 平均延迟差异
	diff_max = abs(rtt_0[2] - rtt_1[2])  # 最大延迟差异

	if nice_avg_latency == -1 and nice_max_latency == -1:  # 初始状态
		nice_avg_latency = threshold_avg
		nice_max_latency = threshold_max

	# 基于平均延迟差异和最大延迟差异做判断
	if diff_avg > threshold_avg or diff_max > threshold_max:	# 静态的判断（阈值法）为上限
		# print("High network link latency, check the network status...")
		print(f'rtt_0: {rtt_0}\nrtt_1: {rtt_1}')
		return False
	elif (rtt_1[1] > (nice_avg_latency * (1 - alpha) + (threshold_avg * alpha)) or
			rtt_1[2] > (nice_max_latency * (1 - alpha) + (threshold_max * alpha))):	# 动态的判断
		# print("High network link latency, check the network status...")
		print(f'rtt_0: {rtt_0}\nrtt_1: {rtt_1}')
		return False
	else:
		nice_avg_latency = alpha * rtt_0[1] + (1 - alpha) * nice_avg_latency
		nice_max_latency = alpha * rtt_0[2] + (1 - alpha) * nice_max_latency
		# print("stability network link latency...")

		return True


def check_latency():
	global target

	print('High network link latency, Check the network status...')
	if target == '':
		target = input('Please input the commend of checking latency: ').strip()	# 例如：'h1 ping -c 6 h5'
	if target == '':	# 如果用户没有输入，就使用默认的
		target = 'h1 ping -c 6 h5'

	# result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)	# 以文本形式捕获输出到变量，而不是控制台
	mininet.sendline(target.encode())
	result = mininet.recvregex(r'rtt min/avg/max/mdev = \d+.\d+/\d+.\d+/\d+.\d+/\d+.\d+ ms'.encode())
	# print(result.stdout)
	# 'rtt min/avg/max/mdev = 0.053/0.073/0.126/0.030 ms'

	rtt_0 = re.compile(r'rtt min/avg/max/mdev = (\d+.\d+)/(\d+.\d+)/(\d+.\d+)/(\d+.\d+) ms').search(result.decode()).groups()
	rtt_0 = [float(element) for element in rtt_0]

	send_packet(packet)
	sleep(1.5)

	# result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)
	mininet.sendline(target.encode())
	result = mininet.recvregex(r'rtt min/avg/max/mdev = \d+.\d+/\d+.\d+/\d+.\d+/\d+.\d+ ms'.encode())
	# print(result)
	rtt_1 = re.compile(r'rtt min/avg/max/mdev = (\d+.\d+)/(\d+.\d+)/(\d+.\d+)/(\d+.\d+) ms').search(result.decode()).groups()
	rtt_1 = [float(element) for element in rtt_1]

	if judge_network_status(rtt_0, rtt_1) is False:
		print('Available log information...')
		return True
	else:
		print('Stability network link latency, may require context packets.')
		return False


def run_mininet():
	"""启动并且赋值给mininet."""
	global mininet
	mininet = Utils.start_mininet(3)	# ODL 不需要 ping


if __name__ == '__main__':

	threading.Thread(target=run_mininet()).start()

	file =  open('logs/interesting.log', 'r')
	log_index = int(input('Please input the log index:'))	# 文件索引, 有些尝试过的log信息就不用再试了

	atexit.register(lambda : print(f'The log_index is \033[1;31m{log_index - 2}\033[0m'))  # 注册退出处理函数, 使用 ANSI 颜色代码
	atexit.register(lambda : file.close())
	atexit.register(lambda : Utils.close_mininet(mininet))

	datas = file.readlines()

	it = iter(datas[log_index:])
	for info_data, packet in zip(it, it):
		log_index += 2
		while True:
			pk = re.compile(r'([0-9a-f]+)').search(packet).group(1).strip()
			if len(pk) < delimited_length['onos_1']:	# 确保连续两条log信息都是输出的测试反馈信息，不是则进行修正
				info_data = packet
				packet = next(it)
				log_index += 1
			else:
				break
		del pk

		# 去除 ANSI 颜色代码
		info_data = re.sub(r'\x1b\[[0-9;]*m', '', info_data).strip()
		packet = re.sub(r'\x1b\[[0-9;]*m', '', packet).strip()

		# 正则提取模块和消息
		info_match = re.search(r'\|\s*(\S+)\s*:\S+:\d+\s*-\s*(.*)', info_data)

		print('')  # 输出空行
		# 让用户检查控制器是否正常运行
		if info_match.group(1) != module:
			input(f'Ensure the \033[1;33m"{info_match.group(1).split("_")[1]}" controller is running\033[0m and press Enter to continue...')

		module = info_match.group(1)  # 模块名
		message = info_match.group(2)  # 日志消息

		flag = False

		# 根据控制器类型不同，执行不同的策略
		if 'ONOS' in module:
			if 'High network link latency' in message:
				flag = check_latency()
			elif 'Topological inconsistency' in message:
				print('Topological inconsistency, notice the output of this program...')

				old_topography = ONOS_TopologyGraph.ONOSTopologyGraph()
				ONOS_TopologyGraph.build_topology_graph(old_topography)

				if len(packet) > delimited_length['onos_1'] and secret == '':
					secret = input('Please input the secret key:')

				# new_lldp = update_onos_lldp(bytearray.fromhex(packet))	# 主要是更新时间戳和签名字段
				send_packet(packet)

				new_topology = ONOS_TopologyGraph.ONOSTopologyGraph()
				ONOS_TopologyGraph.build_topology_graph(new_topology)

				old_topography.compare_topologies(new_topology)
			elif 'raise something' in message:
				send_packet(packet)
				print('Raise something, please check the controller status...')

		elif 'Floodlight' in module:
			if 'High network link latency' in message:
				flag = check_latency()
			elif 'Topological inconsistency' in message:
				print('Topological inconsistency, notice the output of this program...')
				old_topography = FLT_TopologyGraph.FLTTopologyGraph()
				FLT_TopologyGraph.build_topology_graph(old_topography)

				send_packet(packet)

				new_topology = FLT_TopologyGraph.FLTTopologyGraph()
				FLT_TopologyGraph.build_topology_graph(new_topology)

				old_topography.compare_topologies(new_topology)
			elif 'raise something' in message:
				send_packet(packet)
				print('Raise something, please check the controller status...')

		elif 'ODL' in module:
			if 'High network link latency' in message:
				flag = check_latency()
			elif 'Topological inconsistency' in message:
				print('Topological inconsistency, notice the output of this program...')

				old_topography = ODL_TopologyGraph.ODLTopologyGraph()
				ODL_TopologyGraph.build_topology_graph(old_topography)

				send_packet(packet)

				new_topology = ODL_TopologyGraph.ODLTopologyGraph()
				ODL_TopologyGraph.build_topology_graph(new_topology)

				old_topography.compare_topologies(new_topology)
			elif 'raise something' in message:
				send_packet(packet)
				print('Raise something, please check the controller status...')

		else:
			raise RuntimeError('Unknown controller type.')

		if flag:	# 复现到的问题，提示用户
			input(f'\033[1;34mFind useful interesting massage, The index is "{log_index}", Press Enter to continue...\033[0m')

