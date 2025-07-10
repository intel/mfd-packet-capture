# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Tests for `mfd_packet_capture` package: Tcpdump class."""

from pathlib import Path
from textwrap import dedent

import pytest
from mfd_connect import AsyncConnection
from mfd_connect.base import ConnectionCompletedProcess
from mfd_connect.exceptions import ConnectionCalledProcessError, RemoteProcessTimeoutExpired
from mfd_connect.process import RemoteProcess
from mfd_base_tool.exceptions import ToolNotAvailable
from mfd_typing import OSName

from mfd_packet_capture import Tcpdump
from mfd_packet_capture.exceptions import TcpdumpException


class TestTcpdump:
    tcpdump_version_output_linux = dedent(
        """\
    tcpdump version 4.9.3
    libpcap version 1.9.1 (with TPACKET_V3)
    OpenSSL 1.1.1k  FIPS 25 Mar 2021
        """
    )
    tcpdump_version_output_esxi = dedent(
        """\
    tcpdump-uw version 4.9.1-PRE-GIT_2017_09_22
    libpcap version 1.8.1
        """
    )

    tcpdump_packets_output = dedent(
        """\
    00:13:50.1 IP client > host: Flags [P.], seq 2313542211:2313542403, ack 2591824229, win 129, length 192
    00:13:50.2 IP host > client: Flags [P.], seq 1:81, ack 0, win 1020, length 80
    00:13:50.1 IP host > client: Flags [P.], seq 192:256, ack 81, win 129, length 64
    00:13:50.2 IP client > host: Flags [.], ack 256, win 1024, length 0
    00:13:50.2 IP client > host: Flags [P.], seq 81:209, ack 256, win 1024, length 128
        """
    )

    tcpdump_packets_method_output = [
        "00:13:50.1 IP client > host: Flags [P.], seq 2313542211:2313542403, ack 2591824229, win 129, length 192",
        "00:13:50.2 IP host > client: Flags [P.], seq 1:81, ack 0, win 1020, length 80",
        "00:13:50.1 IP host > client: Flags [P.], seq 192:256, ack 81, win 129, length 64",
        "00:13:50.2 IP client > host: Flags [.], ack 256, win 1024, length 0",
        "00:13:50.2 IP client > host: Flags [P.], seq 81:209, ack 256, win 1024, length 128",
    ]

    tcpdump_no_packets_output = dedent(
        """\
    listening on 'Interface Name'
        """
    )

    @pytest.fixture
    def tcpdump(self, mocker):
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump.check_if_available",
            mocker.create_autospec(Tcpdump.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump._get_tool_exec_factory",
            mocker.create_autospec(Tcpdump._get_tool_exec_factory, return_value="tcpdump"),
        )
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump.get_version",
            mocker.create_autospec(Tcpdump.get_version),
        )

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.LINUX

        tcpdump_obj = Tcpdump(connection=conn, interface_name="eth0")
        mocker.stopall()

        return tcpdump_obj

    @pytest.fixture
    def tcpdump_no_interface_name(self, mocker):
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump.check_if_available",
            mocker.create_autospec(Tcpdump.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump._get_tool_exec_factory",
            mocker.create_autospec(Tcpdump._get_tool_exec_factory, return_value="tcpdump"),
        )
        mocker.patch(
            "mfd_packet_capture.tcpdump.Tcpdump.get_version",
            mocker.create_autospec(Tcpdump.get_version),
        )

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.LINUX

        tcpdump_obj = Tcpdump(connection=conn)
        mocker.stopall()

        return tcpdump_obj

    @pytest.mark.parametrize("os_name, result,", [(OSName.LINUX, "tcpdump"), (OSName.ESXI, "tcpdump-uw")])
    def test__get_tool_exec_factory(self, tcpdump, os_name, result):
        tcpdump._connection.get_os_name.return_value = os_name
        assert tcpdump._get_tool_exec_factory() == result

    def test_get_version_linux(self, tcpdump):
        tcpdump._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=self.tcpdump_version_output_linux, stderr=""
        )

        assert tcpdump.get_version() == "4.9.3"

    def test_get_version_esxi(self, tcpdump):
        tcpdump._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=self.tcpdump_version_output_esxi, stderr=""
        )

        assert tcpdump.get_version() == "4.9.1-PRE-GIT_2017_09_22"

    def test_get_version_missing(self, tcpdump):
        tcpdump._connection.execute_command.return_value = ConnectionCompletedProcess(args="", stdout="")

        with pytest.raises(TcpdumpException, match="Version not found."):
            tcpdump.get_version()

    def test_check_is_available(self, tcpdump):
        tcpdump._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=self.tcpdump_version_output_linux, stderr=""
        )

        tcpdump.check_if_available()

    def test_check_is_available_failure(self, tcpdump):
        tcpdump._connection.execute_command.return_value = ConnectionCompletedProcess(args="", stdout="")

        with pytest.raises(ToolNotAvailable):
            tcpdump.check_if_available()

    def test_start(self, tcpdump, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tcpdump.start(additional_args="-c 3")
        tcpdump._connection.start_process.return_value = mocker.Mock(running=False, stdout_text="Correct output")
        tcpdump._connection.start_process.assert_called_with(command="tcpdump -i eth0  -c 3")

    def test_start_within_namespace(self, tcpdump, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tcpdump.start(additional_args="-c 3", namespace="ns1")
        tcpdump._connection.start_process.return_value = mocker.Mock(running=False, stdout_text="Correct output")
        tcpdump._connection.start_process.assert_called_with(command="ip netns exec ns1 tcpdump -i eth0  -c 3")

    def test_start_no_interface_name(self, tcpdump_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tcpdump_no_interface_name.start(additional_args="-c 3", filters="-i eth0")
        tcpdump_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Correct output"
        )
        tcpdump_no_interface_name._connection.start_process.assert_called_with(command="tcpdump -i eth0 -c 3")

    def test_start_problem(self, tcpdump, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tcpdump._connection.start_process.side_effect = ConnectionCalledProcessError
        with pytest.raises(TcpdumpException, match="Problem with execution of tcpdump command"):
            tcpdump.start(additional_args="-c 3")
        tcpdump._connection.start_process.assert_called_with(command="tcpdump -i eth0  -c 3")

    def test_start_problem_no_interface_name(self, tcpdump_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tcpdump_no_interface_name._connection.start_process.side_effect = ConnectionCalledProcessError
        with pytest.raises(TcpdumpException, match="Problem with execution of tcpdump command"):
            tcpdump_no_interface_name.start(additional_args="-c 3", filters="-i eth0")
        tcpdump_no_interface_name._connection.start_process.assert_called_with(command="tcpdump -i eth0 -c 3")

    def test_start_not_running(self, tcpdump, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tcpdump._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Cannot bind address.", stderr_text=""
        )
        with pytest.raises(TcpdumpException, match="Tcpdump is not running"):
            tcpdump.start(additional_args="-c 3")
        tcpdump._connection.start_process.assert_called_with(command="tcpdump -i eth0  -c 3")

    def test_start_not_running_no_interface_name(self, tcpdump_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tcpdump_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Cannot bind address.", stderr_text=""
        )
        with pytest.raises(TcpdumpException, match="Tcpdump is not running"):
            tcpdump_no_interface_name.start(additional_args="-c 3", filters="-i eth0")
        tcpdump_no_interface_name._connection.start_process.assert_called_with(command="tcpdump -i eth0 -c 3")

    def test_start_invalid_args(self, tcpdump, mocker):
        tcpdump_output = "tcpdump: unrecognized option"
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tcpdump._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="", stderr_text=tcpdump_output
        )
        with pytest.raises(TcpdumpException, match="Passed unsupported option as args"):
            tcpdump.start(additional_args="--k")
        tcpdump._connection.start_process.assert_called_with(command="tcpdump -i eth0  --k")

    def test_start_invalid_args_no_interface_name(self, tcpdump_no_interface_name, mocker):
        tcpdump_output = "tcpdump: unrecognized option"
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tcpdump_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="", stderr_text=tcpdump_output
        )
        with pytest.raises(TcpdumpException, match="Passed unsupported option as args"):
            tcpdump_no_interface_name.start(additional_args="--k", filters="-i eth0")
        tcpdump_no_interface_name._connection.start_process.assert_called_with(command="tcpdump -i eth0 --k")

    def test_start_interface_given_twice(self, tcpdump, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tcpdump.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        with pytest.raises(TcpdumpException, match="Interface name was given twice, in interface_name and filters"):
            tcpdump.start(filters="-i eth1", additional_args="-l")

    def test_stop_with_expected_result(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = self.tcpdump_packets_output
        assert tcpdump.stop(process_mock, expected_output=True) == self.tcpdump_packets_method_output

    def test_stop_without_expected_result(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = ""
        process_mock.stderr_text = self.tcpdump_no_packets_output
        assert tcpdump.stop(process_mock, expected_output=False) == []

    def test_stop_with_expected_result_absent(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = ""
        with pytest.raises(TcpdumpException, match="Tcpdump did not return expected output!"):
            tcpdump.stop(process_mock, expected_output=True)

    def test_stop_without_expected_result_present(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = self.tcpdump_packets_output
        with pytest.raises(TcpdumpException, match="Tcpdump unexpectedly returned output!"):
            tcpdump.stop(process_mock, expected_output=False)

    def test_read_tcpdump_packets_success(self, tcpdump, mocker):
        test_path = Path("a")
        tcpdump._connection.path(test_path).exists = mocker.Mock(return_value=True)
        tcpdump._connection.execute_command = mocker.Mock(
            return_value=ConnectionCompletedProcess(args=[], stdout=self.tcpdump_packets_output, return_code=0)
        )
        assert tcpdump.read_tcpdump_packets(test_path) == self.tcpdump_packets_method_output

    def test_read_tcpdump_packets_success_within_namespace(self, tcpdump, mocker):
        test_path = Path("a")
        tcpdump._connection.path(test_path).exists = mocker.Mock(return_value=True)
        tcpdump._connection.execute_command = mocker.Mock(
            return_value=ConnectionCompletedProcess(args=[], stdout=self.tcpdump_packets_output, return_code=0)
        )
        output = tcpdump.read_tcpdump_packets(test_path, namespace="ns1")
        assert output == self.tcpdump_packets_method_output
        tcpdump._connection.execute_command.assert_called_with(
            "ip netns exec ns1 tcpdump -r a -nvv", expected_return_codes=None, stderr_to_stdout=True
        )

    def test_read_tcpdump_packets_wrong_path(self, tcpdump, mocker):
        test_path = Path("a")
        tcpdump._connection.path(test_path).exists = mocker.Mock(return_value=False)

        with pytest.raises(TcpdumpException, match="a not found"):
            tcpdump.read_tcpdump_packets(test_path)

    def test__stop_tcpdump(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        tcpdump._stop_tcpdump(process_mock)
        process_mock.stop.assert_called_with(5)

    def test__stop_tcpdump_timeout(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.stop.side_effect = RemoteProcessTimeoutExpired
        tcpdump._stop_tcpdump(process_mock)
        process_mock.stop.assert_called_with(5)

    def test__kill_tcpdump(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        tcpdump._kill_tcpdump(process_mock)
        process_mock.kill.assert_called_with(5)

    def test__kill_tcpdump_timeout(self, tcpdump, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.kill.side_effect = RemoteProcessTimeoutExpired
        tcpdump._kill_tcpdump(process_mock)
        process_mock.kill.assert_called_with(5)
