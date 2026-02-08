import numpy as np
from bitarray import bitarray
from loguru import logger
from pwn import process
from scapy.all import *
from typing import Dict, List, Tuple

import Mutators

'''
配置代码执行属性
'''
# 将 RuntimeWarning 作为异常来处理，便于被try-except处理
warnings.filterwarnings("error", category=RuntimeWarning)

class MutatorManager:
    def __init__(self, mininet_subprocess: process, malicious_host, delimited_length: Dict, lldp_mutation_iteration_max):
        # 初始化操作符群体
        self.operator_names: List[str] = Mutators.mutator_names
        self.operator_num = len(self.operator_names)

        # 处理种群数据，x 代表每个粒子的概率，v 代表速度
        self.swarm_num = 3  # 定义3个操作符群体
        self.x_max, self.x_min = 0.99, 0.01  # 位置（概率）最大最小值
        self.v_max, self.v_min = 0.9, -0.9  # 速度最大最小值
        self.RAND_C = np.random.uniform(0, 1)  # 随机因子
        # self.RAND_C = lambda: np.random.uniform(0, 1)  # 每次都调用然后随机比较好？
        # self.lldp_mutation_iteration_max = 17  # 变异次数，太大影响场景的布置，太小影响效率
        self.lldp_mutation_iteration_max = lldp_mutation_iteration_max
        self.lldp_mutation_iteration_now: int = 0  # 当前迭代次数
        self.w_init = 0.9  # 初始权重大最开始才能多遍历，少局部最优
        self.w_end = 0.4

        # 初始化操作符效率，三维列表：种群-操作符-属性（也是三个：执行次数、有趣次数、效率）
        self.operators_eff = [[
            [1, 0, 0.0] for __ in range(self.operator_num)  # 初始化操作符效率，1是为了避免后续的除0错误
        ] for _ in range(self.swarm_num)]

        # x 代表每个粒子的概率（归一后），v 代表速度
        self.x_now = [[random.uniform(self.x_min, self.x_max) for _ in range(self.operator_num)] for __ in range(self.swarm_num)]  # 粒子位置（概率）、当前执行次数、有趣次数、效率
        self.v_now = [[random.uniform(self.v_min, self.v_max) for _ in range(self.operator_num)] for __ in range(self.swarm_num)]
        for swarm in range(self.swarm_num):
            sum_data = sum(self.x_now[swarm])
            for i in range(self.operator_num):
                self.x_now[swarm][i] = self.x_now[swarm][i] / sum_data

        self.L_best = [[[0.0, 0.0] for _ in range(self.operator_num)] for __ in range(self.swarm_num)]  # 局部最优，以列（单个粒子）的大小标准去比较，存储粒子单位最佳的 "位置, 效率"
        self.G_best = [[0.0, 0.0] for _ in range(self.operator_num)]  # 全局最优，存储粒子单位中最佳的 "位置, 效率"

        self.swarm_now = 0  # 当前选择的群体
        self.key_module = 0  # 模块选择
        self.limit_time_sig = 1  # 模拟是否开启MOpt

        # 用于后续处理发包
        self.mininet_subprocess: process = mininet_subprocess
        self.malicious_host: str = malicious_host
        self.delimited_length: Dict = delimited_length


    def update_MOPT(self):
        """
        用于更新变异粒子群优化的函数.
        """
        operator_finds_puppet = [0 for _ in range(self.operator_num)]  # 初始化操作符总发现有趣样例计数
        total_finds_puppet = 0  # 初始化操作符总发现计数
        probability_now = [[0.0 for _ in range(self.operator_num)] for __ in range(self.swarm_num)]  # 初始化转盘式概率和

        # 更新当前迭代次数, TODO: 导致无限循环迭代？
        self.lldp_mutation_iteration_now += 1
        if self.lldp_mutation_iteration_now > self.lldp_mutation_iteration_max:
            self.lldp_mutation_iteration_now = 0

        # 更新权重值
        w_now = (self.w_init - self.w_end) * (self.lldp_mutation_iteration_max - self.lldp_mutation_iteration_now) / self.lldp_mutation_iteration_max + self.w_end

        # 更新操作符效率和局部最优解 L_best
        for i in range(self.swarm_num):
            for j in range(self.operator_num):
                operator_finds_puppet[j] += self.operators_eff[i][j][1]  # 更新操作符总发现有趣样例计数
                total_finds_puppet += self.operators_eff[i][j][1]  # 更新总发现有趣样例计数

                self.operators_eff[i][j][2] = self.operators_eff[i][j][1] / self.operators_eff[i][j][0]  # 计算效率
                if self.operators_eff[i][j][2] > self.L_best[i][j][1]:
                    self.L_best[i][j] = [self.x_now[i][j], self.operators_eff[i][j][2]]


        # 更新全局最优解 G_best, 困惑，为什么不比较效率直接更新全局最优解
        for i in range(self.operator_num):
            if operator_finds_puppet[i]:
                self.G_best[i][0] = operator_finds_puppet[i] / total_finds_puppet

        # 遍历每个粒子群，更新速度和位置
        for tmp_swarm in range(self.swarm_num):
            x_temp = 0.0
            for i in range(self.operator_num):
                # 更新速度 v_now
                self.v_now[tmp_swarm][i] = (
                        w_now * self.v_now[tmp_swarm][i]
                        + self.RAND_C * (self.L_best[tmp_swarm][i][0] - self.x_now[tmp_swarm][i])
                        + self.RAND_C * (self.G_best[i][0] - self.x_now[tmp_swarm][i])
                )
                # 更新位置 x_now
                self.x_now[tmp_swarm][i] += self.v_now[tmp_swarm][i]
                self.x_now[tmp_swarm][i] = min(max(self.x_now[tmp_swarm][i], self.x_min), self.x_max)
                x_temp += self.x_now[tmp_swarm][i]

            # 归一化位置值并计算总概率
            for i in range(self.operator_num):
                self.x_now[tmp_swarm][i] /= x_temp
                if i != 0:
                    probability_now[tmp_swarm][i] = (
                            probability_now[tmp_swarm][i - 1] + self.x_now[tmp_swarm][i]
                    )
                else:
                    probability_now[tmp_swarm][i] = self.x_now[tmp_swarm][i]

            # 验证每个群体的概率总和正确性
            if not (0.97 <= probability_now[tmp_swarm][self.operator_num - 1] <= 1.03):
                raise ValueError("ERROR probability.")


    def select_swarm_init(self, swarm_init_times: int):
        """初始化, 先都运行一下看看, 然后随机选择一个群体."""
        logger.info("Initialise selected swarm.")
        for i in range(self.swarm_num):
            yield i  # 生成器，返回当前群体索引，一个函数中有几次 yield 会被调用就返回多少个元素

        for i in range(swarm_init_times):
            yield random.choice(range(self.swarm_num))

    def select_best_swarm(self):
        """选择效率最高的群体用于下一轮模糊测试，"""

        logger.trace(f'\nRatio of swarms:\n' + '-' * 80)

        # 记录最大效率的种群和值
        best_swarm = 0
        max_ratio = 0.0

        # 遍历每个 swarm 计算比值之和，并找出最大值的 swarm
        for swarm_idx, spec_swarm_data in enumerate(self.operators_eff):
            total_calls = sum([operator_values[0] for operator_values in spec_swarm_data])  # 累加调用次数
            total_interesting = sum([operator_values[1] for operator_values in spec_swarm_data])  # 累加有趣结果

            assert total_calls > 0  # 确保调用次数不为 0，避免除零错误
            ratio: float = total_interesting / total_calls
            logger.debug(f"swarm: {swarm_idx}\nratio: {ratio}, max_ratio: {max_ratio}")
            if ratio > max_ratio:
                max_ratio = ratio
                best_swarm = swarm_idx
        return best_swarm


    def select_operator(self, chosen_swarm: int) -> int:
        """概率选择操作符."""
        return random.choices(range(self.operator_num), self.x_now[chosen_swarm])[0]


    def swarm_fuzz(self, chosen_swarm: int, lldp: str):
        """
        在一个种群下, 针对一个包多次执行变异，降低性能损失和提升概率分布的准确率.
        :param chosen_swarm:
        :param lldp:
        :return: 变异后的lldp包，选择的种群，执行的操作符顺序
        """
        temp_mutated_lldp: List[bytes] = []
        operator_order: List[int] = []
        for _ in range(self.lldp_mutation_iteration_max):
            tmp_data = self.execute_mutator(self.select_operator(chosen_swarm), lldp)
            temp_mutated_lldp.append(tmp_data[0])
            operator_order.append(tmp_data[1])

        return temp_mutated_lldp, chosen_swarm, operator_order

    def execute_mutator(self, chosen_operator_enum, lldp: str) -> Tuple[bytes, int]:
        """选择并执行变异函数."""
        method = getattr(Mutators, self.operator_names[chosen_operator_enum])  # 使用getattr动态获取同名函数并调用
        # parameters = inspect.signature(method).parameters
        logger.trace("parameters: {}", method.__name__)  # 获取函数签名(参数，返回值), TODO: 理解该 Python 函数
        logger.trace("chosen operator enum: {}, ", chosen_operator_enum)

        if (len(lldp) < self.delimited_length['onos_1']
                or self.delimited_length['onos_1'] < len(lldp) < self.delimited_length['floodlight']):  # onos 或者floodlight 的普通 LLDP 包
            # 根据选择的变异函数来确定变异的单元
            if 'bit' in self.operator_names[chosen_operator_enum]:
                tmp_lldp = bitarray('')
                tmp_lldp.frombytes(bytes.fromhex(lldp))   # bitarray 的 frombytes 函数不返回值，是在原对象基础上修改的
                mutation_index = random.randint(0, len(tmp_lldp) - 1)  # TODO: 变异下标优化选择
                temp_lldp: bitarray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp.tobytes()
            else:
                tmp_lldp = bytearray.fromhex(lldp)
                mutation_index = random.randint(0, len(tmp_lldp) - 1)  # TODO: 变异下标优化选择
                temp_lldp: bytearray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp
        elif self.delimited_length['floodlight'] < len(lldp) < self.delimited_length['opendaylight']:  # opendaylight 带签名 LLDP 包
            if 'bit' in self.operator_names[chosen_operator_enum]:
                tmp_lldp = bitarray('')
                tmp_lldp.frombytes(bytes.fromhex(lldp))   # bitarray 的 frombytes 函数不返回值，是在原对象基础上修改的
                while True:
                    mutation_index = random.randint(0, len(tmp_lldp) - 1)
                    if not (86 * 4 <= mutation_index < 166 * 4):
                        break
                temp_lldp: bitarray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp.tobytes()
            else:
                tmp_lldp = bytearray.fromhex(lldp)
                while True:
                    mutation_index = random.randint(0, len(tmp_lldp) - 1)
                    if not (86 <= mutation_index < 166):
                        break
                temp_lldp: bytearray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp
        elif self.delimited_length['opendaylight'] < len(lldp) < self.delimited_length['onos_2']:   # ONOS 的带签名 LLDP 包
            if 'bit' in self.operator_names[chosen_operator_enum]:
                tmp_lldp = bitarray('')
                tmp_lldp.frombytes(bytes.fromhex(lldp))   # bitarray 的 frombytes 函数不返回值，是在原对象基础上修改的
                while True:
                    mutation_index = random.randint(0, len(tmp_lldp) - 1)  # TODO: 变异下标优化选择
                    if not (164 * 4 <= mutation_index < 180 * 4 or 180 * 4 <= mutation_index < 256 * 4):
                        break
                temp_lldp: bitarray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp.tobytes()
            else:
                tmp_lldp = bytearray.fromhex(lldp)
                while True:
                    mutation_index = random.randint(0, len(tmp_lldp) - 1)  # 保证不变异时间戳和签名, TODO: 签名的长度和类型是确定的, 对于变异后改变该tlv的需要处理（改变其他tlv的长度或者长度值会导致该情况）
                    if not (164 <= mutation_index < 180 or 180 <= mutation_index < 256):
                        break
                temp_lldp: bytearray = method(tmp_lldp, mutation_index)
                mutation_lldp = temp_lldp
        else:
            raise ValueError("Invalid LLDP Packet.")

        del temp_lldp, tmp_lldp
        logger.debug("mutated lldp: {}", mutation_lldp.hex())
        return mutation_lldp, chosen_operator_enum
