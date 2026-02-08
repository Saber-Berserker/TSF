from pwn import process, context

context.log_level = 'debug'

floodlight = process(['sudo', '-iu', 'ylc'])
floodlight.sendline(b'cd ~/floodlight')
floodlight.sendline(b'java -jar target/floodlight.jar')
floodlight.recvuntil(b'Starting DebugServer on')
# floodlight.interactive()

mininet_close = process(['mn', '-c'])
mininet_close.recvrepeat(0.5)
if mininet_close.poll() is None:
    mininet_close.kill()

# noinspection SpellCheckingInspection
mininet_process = process(
    ['mn', '--custom', 'topologies/mix_topo.py', '--topo', 'mytopo', '--controller', 'remote'])
try:
    mininet_process.recvuntil(b"Starting CLI:")
except EOFError:  # 有时候会存在文件残留，导致第一次启动是清理动作
    mininet_process.wait()  # 等待 mininet 进程正常结束
    # noinspection SpellCheckingInspection
    mininet_process = process(
        ['mn', '--custom', 'topologies/mix_topo.py', '--topo', 'mytopo', '--controller', 'remote'])
    mininet_process.recvuntil(b"Starting CLI:")
mininet_process.sendline(b'pingall')
mininet_process.recvuntil(b"Results:")