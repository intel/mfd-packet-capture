# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Tests for `mfd_packet_capture` package: Tshark class."""

from textwrap import dedent

import pytest
from mfd_connect import AsyncConnection
from mfd_connect.base import ConnectionCompletedProcess
from mfd_connect.exceptions import ConnectionCalledProcessError
from mfd_connect.process import RemoteProcess
from mfd_base_tool.exceptions import ToolNotAvailable
from mfd_typing import OSType, OSName

from mfd_packet_capture.exceptions import TsharkException
from mfd_packet_capture.tshark import Tshark


class TestTshark:
    tshark_version_output = dedent(
        """\
    TShark (Wireshark) 3.2.3 (Git v3.2.3 packaged as 3.2.3-1)

    Copyright 1998-2020 Gerald Combs <gerald@wireshark.org> and contributors.
    License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/gpl-2.0.html>
    This is free software; see the source for copying conditions. There is NO
    warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Compiled (64-bit) with libpcap, with POSIX capabilities (Linux), with libnl 3,
    with GLib 2.64.2, with zlib 1.2.11, with SMI 0.4.8, with c-ares 1.15.0, with Lua
    5.2.4, with GnuTLS 3.6.13 and PKCS #11 support, with Gcrypt 1.8.5, with MIT
    Kerberos, with MaxMind DB resolver, with nghttp2 1.40.0, with brotli, with LZ4,
    with Zstandard, with Snappy, with libxml2 2.9.10.

    Running on Linux 5.4.0-67-generic, with Intel(R) Xeon(R) Gold 6139 CPU @ 2.30GHz
    (with SSE4.2), with 15763 MB of physical memory, with locale en_US, with libpcap
    version 1.9.1 (with TPACKET_V3), with GnuTLS 3.6.13, with Gcrypt 1.8.5, with
    brotli 1.0.7, with zlib 1.2.11, binary plugins supported (0 loaded).

    Built using gcc 9.3.0."""
    )

    tshark_packets_output = dedent(
        """
    1   0.000000 1.1.1.1 → 20.20.20.20  TLSv1.2 392 Application Data
    2   0.017313 30.30.30.30 → 20.20.20.20  TLSv1.2 99 Application Data
    3   0.018704 30.30.30.30 → 20.20.20.20  TLSv1.2 118 Application Data
    4   0.018726  20.20.20.20 → 30.30.30.30 TCP 54 61191 → 443 [ACK] Seq=1 Ack=110 Win=254 Len=0
    5   0.019515  20.20.20.20 → 30.30.30.30 TLSv1.2 92 Application Data
    """
    )
    tshark_packets_method_output = [
        "1   0.000000 1.1.1.1 → 20.20.20.20  TLSv1.2 392 Application Data",
        "2   0.017313 30.30.30.30 → 20.20.20.20  TLSv1.2 99 Application Data",
        "3   0.018704 30.30.30.30 → 20.20.20.20  TLSv1.2 118 Application Data",
        "4   0.018726  20.20.20.20 → 30.30.30.30 TCP 54 61191 → 443 [ACK] Seq=1 Ack=110 Win=254 Len=0",
        "5   0.019515  20.20.20.20 → 30.30.30.30 TLSv1.2 92 Application Data",
    ]

    tshark_no_packets_output = dedent(
        """
    Capturing on 'Interface name'
    """
    )

    @pytest.fixture
    def tshark(self, mocker):
        mocker.patch(
            "mfd_packet_capture.tshark.Tshark.check_if_available",
            mocker.create_autospec(Tshark.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.tshark.Tshark._get_tool_exec_factory",
            mocker.create_autospec(Tshark._get_tool_exec_factory, return_value="tshark"),
        )
        mocker.patch("mfd_packet_capture.tshark.Tshark.get_version", mocker.create_autospec(Tshark.get_version))

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.WINDOWS

        tshark_obj = Tshark(connection=conn, interface_name='"Ethernet 3"')
        tshark_obj._tool_exec = "c:\\tmp\\tshark.exe"
        mocker.stopall()
        return tshark_obj

    @pytest.fixture
    def tshark_no_interface_name(self, mocker):
        mocker.patch(
            "mfd_packet_capture.tshark.Tshark.check_if_available",
            mocker.create_autospec(Tshark.check_if_available),
        )
        mocker.patch(
            "mfd_packet_capture.tshark.Tshark._get_tool_exec_factory",
            mocker.create_autospec(Tshark._get_tool_exec_factory, return_value="tshark"),
        )
        mocker.patch("mfd_packet_capture.tshark.Tshark.get_version", mocker.create_autospec(Tshark.get_version))

        conn = mocker.create_autospec(AsyncConnection)
        conn.get_os_name.return_value = OSName.WINDOWS

        tshark_obj = Tshark(connection=conn)
        tshark_obj._tool_exec = "c:\\tmp\\tshark.exe"
        mocker.stopall()
        return tshark_obj

    @pytest.mark.parametrize("os_type, result,", [(OSType.WINDOWS, "tshark.exe"), (OSType.POSIX, "tshark")])
    def test__get_tool_exec_factory(self, tshark, os_type, result):
        tshark._connection.get_os_type.return_value = os_type
        assert tshark._get_tool_exec_factory() == result

    def test_get_version(self, tshark):
        tshark._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=self.tshark_version_output, stderr=""
        )
        assert tshark.get_version() == "3.2.3 (Git v3.2.3 packaged as 3.2.3-1)"

    def test_get_version_missing(self, tshark):
        tshark._connection.execute_command.return_value = ConnectionCompletedProcess(args="", stdout="")
        with pytest.raises(TsharkException, match="Version not found."):
            tshark.get_version()

    def test_check_is_available(self, tshark):
        tshark._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=self.tshark_version_output, stderr=""
        )
        tshark.check_if_available()

    def test_check_is_available_failure(self, tshark):
        tshark._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout="Command 'tshark' not found, did you mean:", stderr=""
        )
        with pytest.raises(ToolNotAvailable):
            tshark.check_if_available()

    def test_start(self, tshark, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tshark.start(additional_args="-l")
        tshark._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -l',
            log_file=True,
            shell=True,
        )

        tshark._connection.start_process.reset_mock()
        tshark.start(capture_filters="ether src 00:11:22:33:44:55 and broadcast", additional_args="-n -c 1")
        tshark._connection.start_process.assert_called_with(
            command="c:\\tmp\\tshark.exe -i \"Ethernet 3\" -f 'ether src 00:11:22:33:44:55 and broadcast' -n -c 1",
            log_file=True,
            shell=True,
        )

    def test_start_no_interface_name(self, tshark_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tshark_no_interface_name.start(additional_args="-c 3", filters='-i "Ethernet 3"')
        tshark_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Correct output"
        )
        tshark_no_interface_name._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -c 3', log_file=True, shell=True
        )

    def test_start_problem(self, tshark, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tshark._connection.start_process.side_effect = ConnectionCalledProcessError
        with pytest.raises(TsharkException, match="Problem with execution of tshark command"):
            tshark.start(additional_args="-l")
        tshark._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -l',
            log_file=True,
            shell=True,
        )

    def test_start_problem_no_interface_name(self, tshark_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        tshark_no_interface_name._connection.start_process.side_effect = ConnectionCalledProcessError
        with pytest.raises(TsharkException, match="Problem with execution of tshark command"):
            tshark_no_interface_name.start(additional_args="-l", filters='-i "Ethernet 3"')
        tshark_no_interface_name._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -l',
            log_file=True,
            shell=True,
        )

    def test_start_not_running(self, tshark, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tshark._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Cannot bind address.", stderr_text=""
        )
        with pytest.raises(TsharkException, match="TShark is not running"):
            tshark.start(additional_args="-l")
        tshark._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -l',
            log_file=True,
            shell=True,
        )

    def test_start_not_running_no_interface_name(self, tshark_no_interface_name, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tshark_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="Cannot bind address.", stderr_text=""
        )
        with pytest.raises(TsharkException, match="TShark is not running"):
            tshark_no_interface_name.start(additional_args="-l", filters='-i "Ethernet 3"')
        tshark_no_interface_name._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -l',
            log_file=True,
            shell=True,
        )

    @pytest.mark.parametrize(
        "tshark_output",
        [
            "invalid option --k",
            "tshark: The capture session could not be initiated on interface 'temp'",
            "tshark: The capture session could not be initiated on interface 'unknown' (No such device exists).",
            "option requires an argument -- 'i'",
        ],
    )
    def test_start_invalid_args(self, tshark, mocker, tshark_output):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tshark._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="", stderr_text=tshark_output
        )
        with pytest.raises(TsharkException, match="Passed unsupported option as args"):
            tshark.start(additional_args="-B x")
        tshark._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -B x',
            log_file=True,
            shell=True,
        )

    @pytest.mark.parametrize(
        "tshark_output",
        [
            "invalid option --k",
            "tshark: The capture session could not be initiated on interface 'temp'",
            "tshark: The capture session could not be initiated on interface 'unknown' (No such device exists).",
            "option requires an argument -- 'i'",
        ],
    )
    def test_start_invalid_args_no_interface_name(self, tshark_no_interface_name, mocker, tshark_output):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = False
        tshark_no_interface_name._connection.start_process.return_value = mocker.Mock(
            running=False, stdout_text="", stderr_text=tshark_output
        )
        with pytest.raises(TsharkException, match="Passed unsupported option as args"):
            tshark_no_interface_name.start(additional_args="-B x", filters='-i "Ethernet 3"')
        tshark_no_interface_name._connection.start_process.assert_called_with(
            command='c:\\tmp\\tshark.exe -i "Ethernet 3" -B x',
            log_file=True,
            shell=True,
        )

    def test_start_interface_given_twice(self, tshark, mocker):
        timeout_mocker = mocker.patch("mfd_packet_capture.tshark.TimeoutCounter")
        timeout_mocker.return_value.__bool__.return_value = True
        with pytest.raises(TsharkException, match="Interface name was given twice, in interface_name and filters"):
            tshark.start(filters="--interface eth1", additional_args="-l")

    def test_stop_with_expected_result(self, tshark, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = self.tshark_packets_output
        assert tshark.stop(process_mock, expected_output=True) == self.tshark_packets_method_output

    def test_stop_without_expected_result(self, tshark, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = ""
        process_mock.stderr_text = self.tshark_no_packets_output
        assert tshark.stop(process_mock, expected_output=False) == []

    def test_stop_with_expected_result_absent(self, tshark, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = ""
        with pytest.raises(TsharkException, match="Tshark did not return expected output!"):
            tshark.stop(process_mock, expected_output=True)

    def test_stop_without_expected_result_present(self, tshark, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = False
        process_mock.stdout_text = self.tshark_packets_output
        with pytest.raises(TsharkException, match="Tshark unexpectedly returned output!"):
            tshark.stop(process_mock, expected_output=False)

    def test__get_output(self, tshark, mocker):
        log_path = mocker.Mock(read_text=mocker.Mock(return_value="example tshark output"))
        process_mock = mocker.Mock(running=False, log_path=log_path)
        assert tshark._get_output(process_mock) == "example tshark output"

    def test__get_output_from_running_proc(self, tshark, mocker):
        process_mock = mocker.create_autospec(RemoteProcess)
        process_mock.running = True
        with pytest.raises(TsharkException, match="Process is still running."):
            tshark._get_output(process_mock)
