from bitarray import bitarray


def bitarray_left_fill_zero(bitstream: bitarray) -> bitarray:
    """
    左填充 0. 转为 bytes 的时候会向右填充0，这怎么可以呢！

    同时保证源数据不变.
    :param bitstream:
    :return:
    """
    length = len(bitstream)
    if length % 8 != 0:
        bitstream = bitarray('0' * (8 - (length % 8))) + bitstream
    return bitstream


class TLV:
    # 如果在这定义就是类属性，不是实例属性，会导致所有实例共享变量

    def __init__(self, tlv_type_len: bytes) -> None:
        """
        初始化TLV.
        :param tlv_type_len: 把 Type 和 length 一起解析，不然单个比特在字节表示不好处理。
        该变量实际上能把传入的字符串完全存储（不管多长，因此可能需要手动维护传入的 tlv_type_len）。
        """
        # 只有在__init__函数里定义才是实例属性
        self.type = bitarray()
        self.length = bitarray()
        self.oui = bitarray()
        self.subtype = bitarray()
        self.info = bitarray()

        self.type.frombytes(tlv_type_len)  # 直接追加到现有的比特数组中了，因此需要初始化一个空的
        self.type = self.type[:7]  # 该数据结构数组的前 7 位即为 TLV 的类型
        self.length.frombytes(tlv_type_len)
        self.length = self.length[7:]  # 取后 9 位 bits, 此时转为 bytes 需要两个位置


    def get_value_length(self):
        """
        获取标准 value 的长度（length之后字节长）.
        :return:
        """
        tmp = bitarray_left_fill_zero(self.length)  # 左填充 0，不然后续 tobytes 函数转换会出错，同时保证源数据不变
        return int.from_bytes(tmp.tobytes(), 'big')


    def set_value(self, val: bytes):
        """
        设置 value 字段(以字节为长度单位). 即具有子字段的 TLV 的那种 value 字段.

        非厂商自定义 TLV 不作区分子类型，没有 OUI 字段.
        :param val:
        :return:
        """
        try:   # 长度被变异，length 少于代码规定的长度的时候，会导致解析错误
            if self.type != bitarray('1111111'):    # 非厂商定义的 TLV，就不做区分子类型并且没有OUI字段
                self.info.frombytes(val)
            else:
                self.oui.frombytes(val[:3])
                self.subtype.frombytes(val[3:4])
                self.info.frombytes(val[4:])
        except Exception as e:
            raise e


    def get_type(self) -> int:
        """
        获取 TLV 的类型.
        :return:
        """

        if self.type != bitarray('1111111'):
            tmp = bitarray_left_fill_zero(self.type)  # 左填充 0，不然后续 tobytes 函数转换会出错
            return int.from_bytes(tmp.tobytes(), 'big')
        else:
            tmp = bitarray_left_fill_zero(self.subtype)  # 左填充 0，不然后续 tobytes 函数转换会出错
            return int.from_bytes(tmp.tobytes(), 'big') + 100


    def update_information(self, val: bytes) -> None:
        """
        设置信息字段.
        :param val:
        :return:
        """
        try:    # 长度被变异，length 少于代码规定的长度的时候，会导致解析错误
            # length:int = len(self.info) - len(self.subtype) - len(self.oui)
            length: int = self.get_value_length() - int((len(self.subtype) + len(self.oui)) / 8)  # 以防其长度被变异，导致长度不匹配，动态获取长度

            if self.get_type() == 100 + 4:  # timestamp
                self.info = bitarray()
                self.info.frombytes(int(val.hex(), 16).to_bytes(length, 'big'))  # hex 又能变 int，又能转 bytes，很万能
            else:
                self.info = bitarray()
                self.info.frombytes(val[:length])

        except Exception as e:
            raise e


    def build_tlv(self) -> bytearray:
        """
        构建完整的TLV.
        :return:
        """
        # TODO: 是否length和value长度不匹配需要修复？
        return bytearray.fromhex((self.type + self.length + self.oui + self.subtype + self.info).tobytes().hex())

