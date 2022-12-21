import asyncio
import aiosocket
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument('-d', help='Port Name', dest='domain', required=True)
parser.add_argument('-start', help='start port', dest='start', type=int)
parser.add_argument('-end', help='End Port', dest='end', type=int)
args = parser.parse_args()

start = args.start
end = args.end
domain = args.domain

async def port_scan(port):
    async with aiosocket.create_connection((domain, port)) as sock:
        print(f'\033[92m Port is Open {port}')

async def main():
    start_time = time.perf_counter()
    tasks = []
    for port in range(start, end):
        tasks.append(port_scan(port))
    await asyncio.gather(*tasks)
    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f'Execution Time : {execution_time} Seconds')

asyncio.run(main())