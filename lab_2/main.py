from bcc import BPF
import time

print("Загрузка eBPF...")

with open("rtt_monitor.c") as f:
    program = f.read()

bpf = BPF(text=program)

bpf.attach_tracepoint(
    tp="tcp:tcp_rcv_established",
    fn_name="handle_rtt"
)

print("Запущено. Нажми Ctrl+C для выхода\n")

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    rtt_ms = event.rtt_ns / 1_000_000
    print(f"RTT: {rtt_ms:.2f} ms")

bpf["events"].open_ring_buffer(print_event)

try:
    while True:
        bpf.ring_buffer_poll()
except KeyboardInterrupt:
    print("\nОстановлено")
