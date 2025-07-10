# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
import logging
import time

from mfd_connect import RPyCConnection

from mfd_packet_capture import Tcpdump

logging.basicConfig(level=logging.DEBUG)

conn = RPyCConnection(ip="10.10.10.10")
tcpdump = Tcpdump(connection=conn, interface_name="eth0")
logging.debug(tcpdump.get_version())
tcpdump_process = tcpdump.start()
time.sleep(2)
result = tcpdump.stop(tcpdump_process, expected_output=True)
logging.debug(result)