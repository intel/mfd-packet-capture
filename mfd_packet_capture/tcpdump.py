# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Packet Capture module: Tcpdump."""

import logging
import re
from typing import TYPE_CHECKING, List

from mfd_common_libs import os_supported, log_levels, add_logging_level, TimeoutCounter
from mfd_kernel_namespace import add_namespace_call_command
from mfd_base_tool import ToolTemplate
from mfd_base_tool.exceptions import ToolNotAvailable
from mfd_typing import OSName

from mfd_packet_capture.exceptions import TcpdumpException

if TYPE_CHECKING:
    from mfd_connect import Connection
    from mfd_connect.process import RemoteProcess
    from pathlib import Path

logger = logging.getLogger(__name__)
add_logging_level("MODULE_DEBUG", log_levels.MODULE_DEBUG)


class Tcpdump(ToolTemplate):
    """Class for Tcpdump tool."""

    tool_executable_name = {
        OSName.LINUX: "tcpdump",
        OSName.ESXI: "tcpdump-uw",
    }

    @os_supported(OSName.LINUX, OSName.ESXI)
    def __init__(
        self,
        *,
        connection: "Connection",
        interface_name: str = "",
        absolute_path_to_binary_dir: "Path | str | None" = None,
    ):
        """
        Initialize Tcpdump.

        :param connection: mfd-connect object
        :param interface_name: name of the interface to use tcpdump on
        """
        super().__init__(connection=connection, absolute_path_to_binary_dir=absolute_path_to_binary_dir)
        self._interface_name = interface_name

    def _get_tool_exec_factory(self) -> str:
        """
        Get correct tool name.

        :return: Tool exec name
        """
        return self.tool_executable_name[self._connection.get_os_name()]

    def check_if_available(self) -> None:
        """
        Check if tool is available in system.

        :raises ToolNotAvailable when tool not available.
        """
        result = self._connection.execute_command(
            f"{self._tool_exec} --version", expected_return_codes=None, stderr_to_stdout=True
        )

        if f"{self._tool_exec}" not in result.stdout:
            raise ToolNotAvailable(returncode=1, cmd=f"{self._tool_exec} --version", output=result.stdout)

    def get_version(self) -> str:
        """
        Get Tcpdump version.

        :raises Tcpdump exception when version not available.
        """
        result = self._connection.execute_command(
            f"{self._tool_exec} --version", expected_return_codes=None, stderr_to_stdout=True
        ).stdout

        version_regex = r"^(tcpdump)(-uw)? version\s(?P<version>.*)$"
        match = re.search(version_regex, result, re.M)
        if match:
            return match.group("version").rstrip()
        else:
            raise TcpdumpException("Version not found.")

    def start(self, *, filters: str = "", additional_args: str = "", namespace: str | None = None) -> "RemoteProcess":
        """
        Start Tcpdump process with given args.

        :param filters: Parameters that determine which network traffic should be captured.
        :param additional_args: Additional arguments.
        :param namespace: Namespace in which command should be executed.
        :return: Return connection process of run command.
        :raises TcpdumpException: if tcpdump command fails on execution
                                 if tcpdump incorrect args
                                 if interface_name was provided and another interface in filters
        """
        if self._interface_name:
            if re.search(r"-i |--interface ", filters):
                raise TcpdumpException("Interface name was given twice, in interface_name and filters")
            command = f"{self._tool_exec} -i {self._interface_name} {filters} {additional_args}"
        else:
            command = f"{self._tool_exec} {filters} {additional_args}"

        try:
            command = add_namespace_call_command(command, namespace)
            process = self._connection.start_process(command=command)
        except Exception as e:
            raise TcpdumpException("Problem with execution of tcpdump command.") from e

        self._validate_arguments_correctness(process)
        logger.log(level=log_levels.MODULE_DEBUG, msg="Started tcpdump.")
        return process

    def _stop_tcpdump(self, process: "RemoteProcess") -> None:
        try:
            process.stop(5)  # it will wait seconds for process to finish
        except Exception:
            return

    def _kill_tcpdump(self, process: "RemoteProcess") -> None:
        try:
            process.kill(5)  # it will wait seconds for process to finish
        except Exception:
            return

    def stop(self, process: "RemoteProcess", *, expected_output: bool) -> List[str]:
        """
        Stop tcpdump process and report result. Kill tcpdump process if after timeout is still running.

        :param process: OS process with tcpdump.
        :param expected_output: Decision if user expect to have output from command.
        :return: Output of tcpdump command sliced into list of str.
        :raises TcpdumpException: If process after stop and kill is still running.
                                 If process unexpectedly returned output.
                                 If process does not returned output when expected.
        """
        if process.running:
            logger.log(level=log_levels.MODULE_DEBUG, msg="Stopping tcpdump process.")
            self._stop_tcpdump(process)
            # if process is still running, kill forcefully.
            if process.running:
                logger.log(level=log_levels.MODULE_DEBUG, msg="Killing tcpdump process.")
                self._kill_tcpdump(process)
                if process.running:
                    raise TcpdumpException("Problem with kill of tcpdump process")

        result = process.stdout_text

        if result:
            if expected_output:
                return result.strip().splitlines()
            else:
                raise TcpdumpException("Tcpdump unexpectedly returned output!")
        else:
            if expected_output:
                raise TcpdumpException("Tcpdump did not return expected output!")
            else:
                return []

    def _validate_arguments_correctness(self, process: "RemoteProcess") -> None:
        """
        Check correctness of passed arguments after start of process.

        :param process: TcpdumpProcess
        :raises: TcpdumpException if passed incorrect args
        """
        timeout = TimeoutCounter(1)
        while not timeout:
            if not process.running:
                if any(
                    x in process.stderr_text.lower()
                    for x in {
                        "invalid",
                        "was not specified",
                        "could not be initiated",
                        "option requires an argument",
                        "unrecognized option",
                    }
                ):
                    raise TcpdumpException(f"Passed unsupported option as args. {process.stderr_text}")
                else:
                    logger.log(level=log_levels.MODULE_DEBUG, msg=process.stdout_text)
                    raise TcpdumpException("Tcpdump is not running.")

    def read_tcpdump_packets(
        self,
        file_path: "Path",
        additional_args: str = "-nvv",
        namespace: str | None = None,
    ) -> list[str]:
        """
        Read packets from file which was created with other tools e.g pktcap-uw in pcap or pcapng format.

        :param file_path: path to file with raw packets
        :param additional_args: additional args to use while reading packets. -nvv by default
        :param namespace: Namespace in which command should be executed
        :raises TcpdumpException: if command fails on execution
        :return: Output from tcpdump sliced into list of string.
        """
        if self._connection.path(file_path).exists():
            command = f"{self._tool_exec} -r {file_path} {additional_args}"
            command = add_namespace_call_command(command, namespace)
            result = self._connection.execute_command(
                command,
                expected_return_codes=None,
                stderr_to_stdout=True,
            ).stdout
            return result.strip().splitlines()
        else:
            raise TcpdumpException(f"{file_path} not found. Cannot read tcpdump packets.")
