import hashlib
import binascii

# 1. 目标 Hash (你提供的)
TARGET_HASH_HEX = "cf8a4d90673f3c0c3722432ebba91a81"

# 2. 修正后的字符串
#    根据你的 byte[] [85, 114, 105, 123, 118...] 还原
#    注意这里是 "value=" 而不是 "_value="
REAL_INPUT_STR = "Uri{value=openflow:1:1}aa9251f8-c7c0-4322-b8d6-c3a84593bda3"

def verify():
    # 计算 MD5
    calc_bytes = hashlib.md5(REAL_INPUT_STR.encode('utf-8')).digest()
    calc_hex = binascii.hexlify(calc_bytes).decode()

    print(f"输入字符串: '{REAL_INPUT_STR}'")
    print(f"计算出的 MD5: {calc_hex}")
    print(f"报文中的 MD5: {TARGET_HASH_HEX}")

    if calc_hex == TARGET_HASH_HEX:
        print("\n[SUCCESS] 验证完全匹配！")
    else:
        print("\n[FAIL] 仍然不匹配，请检查 UUID 部分是否正确。")

if __name__ == "__main__":
    verify()