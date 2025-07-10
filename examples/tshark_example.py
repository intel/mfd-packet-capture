# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
import logging
import time

from mfd_connect import RPyCConnection

from mfd_packet_capture import Tshark

logging.basicConfig(level=logging.DEBUG)

conn = RPyCConnection(ip="10.10.10.10")
tshark = Tshark(connection=conn, interface_name="eth0")
logging.debug(tshark.get_version())


def simple_flow_example():
    tshark_process = tshark.start(additional_args="-l")
    time.sleep(2)
    result = tshark.stop(tshark_process, expected_output=True)
    logging.debug(result)


def capture_filters_example():
    tshark_process = tshark.start(
        capture_filters="ether src 00:11:22:33:44:55 and broadcast", additional_args="-n -c 1"
    )
    time.sleep(2)
    result = tshark.stop(tshark_process, expected_output=True)
    logging.debug(result)
