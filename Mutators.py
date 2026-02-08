import copy
import random
from typing import List, Dict

from bitarray import bitarray

# 加减法的变异值, 由于字节是0~255，因此不考虑+256导致的符号取反的情况
arith_values: List[int] = [+1, -1, +2, -2, +3, -3, +4, -4, +8, -8, +128, -128, -256, +11, -13]

# 因为 bytearray 的每个元素类型实际上是 int 型，因此这里的特殊值也是 int 型而不是bytes

# 单字节特殊值, FE 是LLDP中一个特殊值
interesting_values: List[bytes] = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0x02, 0x04, 0x08, 0x20, 0x10, 0x0A, 0x0D, 0x1B, 0x55, 0xAA, 0xFE]

# 单字节替换变异字典
mutation_dict: Dict[int, int] = {
    0x00: 0xFF,  # 全零替换为全F
    0xFF: 0x00,  # 全F替换为全零
    0x55: 0xAA,  # 01010101 替换为 10101010
    0xAA: 0x55,  # 10101010 替换为 01010101
    0x01: 0xFE,  # 最小值替换为次最大值
    0xFE: 0x01,  # 次最大值替换为最小值
    0x7F: 0x80,  # 最大正值替换为最小负值
    0x80: 0x7F,  # 最小负值替换为最大正值
    0xDE: 0xAD,  # 特殊标志字节替换为另一常见值
    0xAD: 0xDE,  # 另一常见值替换为特殊标志字节
    0xC0: 0x3F,  # 常见网络字节替换为边界值
    0x3F: 0xC0,  # 边界值替换为常见网络字节
}

# 变异器名称, TODO: 加上 TLV 单位的增删？
mutator_names: List[str] = [
    "bit_flip_1_1",
    "bit_flip_2_1",
    "arith_8_8",
    "insert_interesting_values",
    "replace_interesting_value",
    "delete_byte",
    "dictionary_mutation"
]

def tempBytes2bits(value: bytearray, length: int) -> bitarray:
    bitstream = bitarray()
    bitstream.frombytes(value)
    return bitstream[length * -1:]

# 定义基础的变异策略类
def bit_flip_1_1(bitstream: bitarray, index: int) -> bitarray:
    """
    位翻转：每次翻转一个比特位.
    :param bitstream: 比特流
    :param index: 翻转的比特位索引
    :return: 翻转后的比特流
    """
    new_bitstream = bitstream.copy()    # 复制一份比特流，不然会修改原比特流——可变对象
    new_bitstream[index] = not bitstream[index]  # 翻转该位
    return new_bitstream


def bit_flip_2_1(bitstream: bitarray, index: int) -> bitarray:
    """每次翻转两个相邻的比特位，2bit为一次变异的组，组内变异单位是1bit."""
    new_bitstream = copy.deepcopy(bitstream)

    if index == (len(bitstream) -1):    # 不可加
        new_bitstream[index] = not bitstream[index]
        new_bitstream[index - 1] = not bitstream[index - 1]
    elif index == 0:    # 不可减
        new_bitstream[index] = not bitstream[index]
        new_bitstream[index + 1] = not bitstream[index + 1]
    else:
        change_index_value = random.choice([+1, -1])
        new_bitstream[index] = not bitstream[index]
        new_bitstream[index + change_index_value] = not bitstream[index + change_index_value]

    return new_bitstream


# arith 8/8
def arith_8_8(bytestream: bytearray, index: int) -> bytearray:
    """一字节单位的加减法."""
    new_bytes = copy.deepcopy(bytestream)
    arith_value = random.choice(arith_values)   # TODO: 算法优化

    if abs(arith_value) != 256:
        # 加、减法变异
        new_bytes[index] = (new_bytes[index] + arith_value + 256) % 256    # 防止正、负溢出
    else:
        # -256 的情况
        new_bytes[index] = (-1 * (new_bytes[index] + arith_value)) % 256    # 遇 0 - 256 会出错，需要取余

    return new_bytes


# 从列表中选择一个特殊值插入
def insert_interesting_values(bytestream: bytearray, index: int) -> bytearray:
    """
    插入特殊值 (Insert Interesting Values)，改变原字节长度.
    :param bytestream:
    :param index:
    :return:
    """
    new_bytes = copy.deepcopy(bytestream)
    value = random.choice(interesting_values)
    new_bytes.insert(index, value)
    return new_bytes


def replace_interesting_value(bytestream: bytearray, index: int) -> bytearray:
    """将随机字节替换为特殊值."""
    new_bytes = copy.deepcopy(bytestream)
    new_bytes[index] = random.choice(interesting_values)

    return new_bytes


def delete_byte(bytestream: bytearray, index: int) -> bytearray:
    """删除一个字节."""
    new_bytes = copy.deepcopy(bytestream)
    del new_bytes[index]  # del——删除关键字
    return new_bytes


def dictionary_mutation(bytestream: bytearray, index: int) -> bytearray:
    """根据字典将特定字节替换为字典中的值."""
    new_bytes = copy.deepcopy(bytestream)

    # 从选定点到末尾的字节中选择一个需要变异的字节
    for i in range(len(new_bytes) - index):
        if new_bytes[index + i] in mutation_dict:
            new_bytes[index + i] = mutation_dict[new_bytes[index + i]]
            break

    return new_bytes

'''
和PSO一样是属于进化优化策略，不太算变异操作.
PSO通常效率更高，收敛速度较快。而遗传算法的随机变异和交叉操作在探索未知解空间时更具多样性，适合处理复杂的、离散的或组合问题。
'''
# def genetic_algorithm_mutation(data: bytearray, mutation_rate: float) -> bytearray:
#     """使用遗传算法进行变异操作."""
#     mutated_data = bytearray(data)
#     for i in range(len(mutated_data)):
#         if random.random() < mutation_rate:
#             mutated_data[i] = random.randint(0, 255)  # 随机变异某字节
#     return mutated_data
#
#     # 示例
#     mutated_data = genetic_algorithm_mutation(data, 0.1)
#     print(mutated_data)
