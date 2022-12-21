import socket
import argparse
import time

def port_scan(ports, threadcount, domain, port):
    start_time = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    conn = s.connect_ex((domain, port))
    if not conn:
        print(f'\033[92m Port is Open {port}')
    s.close()
    end_time = time.perf_counter()
execution_time = end_time - start_time
print(f'Execution Time : {execution_time} Seconds')