import argparse
from scapy.all import sendp, Raw


def parse_args():
    parser = argparse.ArgumentParser(description="Send a raw packet using Scapy")
    parser.add_argument("hex_data", help="The packet data in bytes (e.g., '\\xff\\xff\\xff\\xff')", type=str)
    # parser.add_argument("--iface", help="The network interface to send on (default: eth0)", default="eth0")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        # 将字符串格式的字节流转换为 bytearray
        byte_stream = bytearray.fromhex(args.hex_data)

        # 构造数据包并发送
        packet = Raw(byte_stream)
        sendp(packet)

    except SyntaxError as e:
        print(f"Error parsing packet data: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    # mininet那个终端有问题，无法直接执行复杂python代码，需要像这样使用额外的python包执行
    main()
