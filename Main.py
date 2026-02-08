import os
import sys
import tomli as tomllib # Python 3.11+ 使用 tomllib，旧版本需
# import tracemalloc  # 分析内存
from typing import Dict

from loguru import logger
from pwn import process, context  # pwntools library

import Utils
from fuzzy import Fuzz_Floodlight, Fuzz_ONOS, Fuzz_ODL

# 配置信息
with open("config.toml", "rb") as f:
    config_file = tomllib.load(f)

config: Dict = {'will_draw': config_file['will_draw'], 'os_username': config_file['os_username'],
                'log_path': config_file['paths']['logs'], 'scenario_path': config_file['paths']['scenarios'],
                'onos_root': config_file['paths']['ONOS_ROOT_DIR'], 'trigger_packet_file': config_file['paths']['trigger_packet'],
                'flt_classes_dir': config_file['paths']['flt_classes_dir'],
                'http_proxy': config_file['network']['proxy_host'] + ':' + config_file['network']['proxy_port'],
                'delimited_length': dict(config_file['ofdp_delimited_length']),
                'tlv_start_index': config_file['tlv_info']['tlv_start_index'],
                'malicious_host': config_file['algorithm']['malicious_host'],
                'get_latency_cmd': config_file['algorithm']['get_latency_cmd'],
                'swarm_extra_init_times': config_file['algorithm']['swarm_total_times'] - config_file['algorithm'][
                    'swarm_iterations'], 'fuzz_scenario_times': config_file['algorithm']['fuzz_scenario_times'],
                'fuzz_lldp_times': config_file['algorithm']['fuzz_lldp_times'],
                'lldp_mutation_iteration_max': config_file['algorithm']['lldp_mutation_iteration_max'],
                'env_constraint_enable': config_file['algorithm']['env_constraint_enable'], 'odl_key': config_file['algorithm']['odl_key'],
                }
del config_file

original_stdout = sys.stdout

# 添加 log
logger.remove()  # 移除Loguru默认的日志处理器
Utils.add_logger(config['log_path'], sys.stdout)

context.log_level = 'debug'  # 调整 pwn 的 log 等级可以输出更多接收的信息
# context.log_console = open('/dev/null', 'w')  # 重定向 pwn 自带 log 到 /dev/null, 禁止标准输出
# sys.stdout = open('/dev/null', 'w')
# sys.stderr = open('/dev/null', 'w')

def fuzz_onos(is_eval: bool = False):
    http_proxy = os.getenv('http_proxy', config['http_proxy'])
    logger.info('http_proxy: ' + http_proxy)
    Fuzz_ONOS.start_fuzzing(config, original_stdout, is_eval)


def fuzz_floodlight(is_eval: bool = False):
    Fuzz_Floodlight.start_fuzzing(config, original_stdout, is_eval)


def fuzz_odl(is_eval: bool = False):
    Fuzz_ODL.start_fuzzing(config, original_stdout, is_eval)
    pass

if __name__ == '__main__':
    controller: process
    mininet: process    # 因为涉及到外部链路，pingall 的时候需要等很久（ping不通），因此尽可能一次性多用 mininet，减少开销
    controller_type: str = ''
    mode_times: int = 0

    # 用户输入模糊测试场景次数
    try:
        logger.info("Please input the type of controller:")
        controller_type = input().lower()

        logger.info("Enable Evaluation Mode: (y/N):")
        mode = input().lower()
        evaluation_mode = True if 'y' in mode else False

    except ValueError:
        logger.error("Invalid input.")
        sys.exit(1)

    # tracemalloc.start()

    if controller_type[:2] == 'on':   # onos
        fuzz_onos(is_eval=evaluation_mode)
    elif controller_type[0] == 'f': # floodlight
        fuzz_floodlight(is_eval=evaluation_mode)
    elif controller_type[:2] == 'od':   # odl
        fuzz_odl(is_eval=evaluation_mode)

    if evaluation_mode:
        logger.info("Please save the evaluation results file before next run.")

    # current, peak = tracemalloc.get_traced_memory()
    # print(f"Current memory: {current / 1024 / 1024:.2f} MB")
    # print(f"Peak memory: {peak / 1024 / 1024:.2f} MB")
    # tracemalloc.stop()

