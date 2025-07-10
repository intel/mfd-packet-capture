# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""PktCap example."""
import logging
from time import sleep
from mfd_connect import RPyCConnection
from mfd_packet_capture.pktcap import PktCap

logging.basicConfig(level=logging.DEBUG)

conn = RPyCConnection(ip="10.10.10.10")
pkt_capture = PktCap(connection=conn, interface_name="vmnic0")

# start capturing
process = pkt_capture.start(additional_args="--count 4")
sleep(10)

# stop capturing
output = pkt_capture.stop(process=process, expected_output=True)
logging.debug(f"output: {output}")
