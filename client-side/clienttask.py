from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
import os
import psutil
import pynvml
import sys

from pprint import pprint

def gputask():
    def get(handle):
        memory_info=pynvml.nvmlDeviceGetMemoryInfo(handle)
        return dict(
            nvmlDeviceGetName=pynvml.nvmlDeviceGetName(handle).decode('utf-8'),
            nvmlDeviceGetMemoryInfo=dict(
                total=memory_info.total,
                free=memory_info.free,
                used=memory_info.used,
            ),
            nvmlDeviceGetUtilizationRates=dict(
                gpu=pynvml.nvmlDeviceGetUtilizationRates(handle).gpu,
                memory=pynvml.nvmlDeviceGetUtilizationRates(handle).memory,
            ),
            nvmlDeviceGetFanSpeed=pynvml.nvmlDeviceGetFanSpeed(handle),
            nvmlDeviceGetPowerManagementLimit=pynvml.nvmlDeviceGetPowerManagementLimit(handle),
            nvmlDeviceGetPowerUsage=pynvml.nvmlDeviceGetPowerUsage(handle),
        )
    try:
        pynvml.nvmlInit()
        return dict(
            nvml_version=pynvml.nvmlSystemGetDriverVersion().decode(),
            nvmlDeviceGetCount=pynvml.nvmlDeviceGetCount(),
            nvmlDevices=[get(pynvml.nvmlDeviceGetHandleByIndex(i)) for i in range(pynvml.nvmlDeviceGetCount())],
        )
        pynvml.nvmlShutdown()
    except:
        return dict(
            nvml_version=None,
        )

def alltasks(ensure_json=True):
    assert psutil._PY3
    res = dict(
        version='0.1.0',
        platform=sys.platform,
        boot_time=psutil.boot_time(),
        loadavg=hasattr(os, 'getloadavg') and os.getloadavg() or None,
        cpu_count=psutil.cpu_count(),
        cpu_freq=psutil.cpu_freq(),
        cpu_percent=psutil.cpu_percent(),
        cpu_stats=psutil.cpu_stats(),
        cpu_times=psutil.cpu_times(),
        cpu_times_percent=psutil.cpu_times_percent(),
        disk_io_counters=psutil.disk_io_counters(),
        disk_partitions=psutil.disk_partitions(),
        disk_usage=[psutil.disk_usage(part.mountpoint) for part in psutil.disk_partitions() if not part.mountpoint.startswith('/var')],
        net_if_addrs=psutil.net_if_addrs(),
        net_if_stats=psutil.net_if_stats(),
        net_io_counters=psutil.net_io_counters(),
        swap_memory=psutil.swap_memory(),
        users=psutil.users(),
        virtual_memory=psutil.virtual_memory(),
    )
    res.update(gputask())
    if ensure_json:
        res = json.loads(json.dumps(res))
    return res


if __name__ == '__main__':
    pprint(alltasks(ensure_json=False))

