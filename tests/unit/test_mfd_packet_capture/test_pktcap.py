# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""PktCap unit tests."""

from textwrap import dedent

import pytest
from mfd_connect import AsyncConnection
from mfd_connect.process import RemoteProcess
from mfd_typing import OSName
from mfd_connect.exceptions import RemoteProcessTimeoutExpired

from mfd_packet_capture.exceptions import PktCapException
from mfd_packet_capture.pktcap import PktCap


class TestPktCap:
    tool_name = "pktcap-uw"

    @pytest.fixture
    def pktcap(self, mocker):
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap.check_if_available",
            mocker.create_autospec(PktCap.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap._get_tool_exec_factory",
            mocker.create_autospec(PktCap._get_tool_exec_factory, return_value=TestPktCap.tool_name),
        )
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap.get_version",
            mocker.create_autospec(PktCap.get_version),
        )

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.ESXI

        pktcap_obj = PktCap(connection=conn, interface_name="foo")
        mocker.stopall()

        return pktcap_obj

    @pytest.fixture
    def pktcap_no_interface_name(self, mocker):
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap.check_if_available",
            mocker.create_autospec(PktCap.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap._get_tool_exec_factory",
            mocker.create_autospec(PktCap._get_tool_exec_factory, return_value=TestPktCap.tool_name),
        )
        mocker.patch(
            "mfd_packet_capture.pktcap.PktCap.get_version",
            mocker.create_autospec(PktCap.get_version),
        )

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.ESXI

        pktcap_obj = PktCap(connection=conn)
        mocker.stopall()

        return pktcap_obj

    def test_start_pktcap(self, pktcap):
        other_args = "--count 4"

        pktcap.start(additional_args=other_args)
        pktcap._connection.start_process.assert_called_with(
            command=f"{TestPktCap.tool_name} --uplink foo --count 4",
            stderr_to_stdout=True,
            shell=True,
            log_file=True,
        )

    def test_start_pktcap_no_interface_name(self, pktcap_no_interface_name):
        other_args = "--count 4"

        pktcap_no_interface_name.start(interface_name="foo", additional_args=other_args)
        pktcap_no_interface_name._connection.start_process.assert_called_with(
            command=f"{TestPktCap.tool_name} --uplink foo --count 4",
            stderr_to_stdout=True,
            shell=True,
            log_file=True,
        )

    def test_start_pktcap_raise(self, pktcap, mocker):
        pktcap._connection.start_process = mocker.Mock(side_effect=Exception)
        with pytest.raises(PktCapException):
            pktcap.start()

    def test_start_pktcap_raise_no_interface_name(self, pktcap_no_interface_name, mocker):
        pktcap_no_interface_name._connection.start_process = mocker.Mock(side_effect=Exception)
        with pytest.raises(PktCapException):
            pktcap_no_interface_name.start(interface_name="foo")

    def test_start_pktcap_interface_name_given_twice(self, pktcap, mocker):
        with pytest.raises(
            PktCapException,
            match="Interface name was given twice, on initialization and in start argument",
        ):
            pktcap.start(interface_name="foo")

    def test_stop_pktcap(self, pktcap, mocker):
        expected_stdout = dedent(
            """
        11:59:06.483959[1] Captured at UplinkRcvKernel point, Checksum not offloaded and verified, length 62.
            Segment[0] ---- 2048 bytes:
            0x0000:  0100 5e00 0002 0000 0c07 ac3f 0800 45c0
            0x0010:  0030 0000 0000 0111 db9d 0a5b f302 e000
            0x0020:  0002 07c1 07c1 001c 75de 0000 1003 0ac8
            0x0030:  3f00 6369 7363 6f00 0000 0a5b f301
        11:59:06.489013[2] Captured at UplinkRcvKernel point, Checksum not offloaded and verified, length 66.
            Segment[0] ---- 2048 bytes:
            0x0000:  a4bf 0164 622b bc4a 5664 4782 0800 4500
            0x0010:  0034 0000 4000 3f06 fc1c 0a66 3746 0a5b
            0x0020:  f3a0 0cbc b849 73cd b7be 709d 4e2e 8010
            0x0030:  6000 c763 0000 0101 080a a156 7310 7cf2
            0x0040:  cefa
        11:59:06.620304[3] Captured at UplinkRcvKernel point, Checksum not offloaded and verified, length 60.
            Segment[0] ---- 2048 bytes:
            0x0000:  0180 c200 0000 6cb2 ae25 dc3d 0027 4242
            0x0010:  0300 0002 023c 21cf bc4a 5664 4780 0000
            0x0020:  07d0 81cf f80b cbdf 9200 8066 0100 1400
            0x0030:  0200 0f00 0000 0000 0000 0000
        11:59:06.733212[4] Captured at UplinkRcvKernel point, Checksum not offloaded and verified, length 66.
            Segment[0] ---- 2048 bytes:
            0x0000:  a4bf 0164 622b bc4a 5664 4782 0800 4500
            0x0010:  0034 ca58 4000 3f06 7cc6 0ad3 ebd6 0a5b
            0x0020:  f3a0 0801 03fd 10f7 d940 a607 1a33 8010
            0x0030:  01fd d1a6 0000 0101 080a aa1b b93f 69db
            0x0040:  2acd
        The name of the uplink is vmnic0.
        To capture 4 packets.
        No server port specifed, select 57734 as the port.
        Output the packet info to console.
        Local CID 2.
        Listen on port 57734.
        Main thread: 330745392000.
        Dump Thread: 330747500288.
        Recv Thread: 330749601536.
        Accept...
        Vsock connection from port 1039 cid 2.
        Receive thread exiting...
        Dump thread exiting...
        Join with dump thread failed.
        Join with recvthread failed.
        Destroying session 15.
        Dumped 4 packet to console, dropped 0 packets.
        Done.
        """
        )
        expected_output = expected_stdout.splitlines()

        mock_process = mocker.create_autospec(RemoteProcess)
        mock_process.stdout_text = expected_stdout
        mock_process.running = False
        mock_process.log_path = mocker.Mock()
        mock_process.log_path.read_text.return_value = expected_stdout
        mock_process.log_file_stream = None

        assert pktcap.stop(process=mock_process, expected_output=True) == expected_output

    def test_stop_pktcap_raise(self, pktcap, mocker):
        mock_process = mocker.create_autospec(RemoteProcess)
        mock_process.running = True
        pktcap._stop_pktcap = mocker.Mock()
        pktcap._kill_pktcap = mocker.Mock()
        with pytest.raises(PktCapException):
            pktcap.stop(process=mock_process, expected_output=False)

    def test_stop_with_expected_result_absent(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = ""
        with pytest.raises(PktCapException, match="pktcap did not return the expected output!"):
            pktcap.stop(process_mock, expected_output=True)

    def test_stop_without_expected_result_present(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = "test output"
        with pytest.raises(PktCapException, match="pktcap expectedly returned output, when it was not expected!"):
            pktcap.stop(process_mock, expected_output=False)

    def test__stop_pktcap(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        pktcap._stop_pktcap(process_mock)
        process_mock.stop.assert_called_with(5)

    def test__stop_pktcap_timeout(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.stop.side_effect = RemoteProcessTimeoutExpired
        pktcap._stop_pktcap(process_mock)
        process_mock.stop.assert_called_with(5)

    def test__kill_pktcap(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        pktcap._kill_pktcap(process_mock)
        process_mock.kill.assert_called_with(5)

    def test__kill_pktcap_timeout(self, pktcap, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.kill.side_effect = RemoteProcessTimeoutExpired
        pktcap._kill_pktcap(process_mock)
        process_mock.kill.assert_called_with(5)
