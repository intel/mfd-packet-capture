# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Packet Capture module: tshark."""

import re

import logging
from typing import List, TYPE_CHECKING

from mfd_base_tool import ToolTemplate
from mfd_base_tool.exceptions import ToolNotAvailable
from mfd_common_libs import log_levels, add_logging_level, TimeoutCounter, os_supported
from mfd_typing import OSType, OSName

from mfd_packet_capture.exceptions import TsharkException

if TYPE_CHECKING:
    from mfd_connect import Connection
    from mfd_connect.process import RemoteProcess
    from pathlib import Path

logger = logging.getLogger(__name__)
add_logging_level("MODULE_DEBUG", log_levels.MODULE_DEBUG)


class Tshark(ToolTemplate):
    """Class for Tshark tool."""

    tool_executable_name = {OSType.WINDOWS: "tshark.exe", OSType.POSIX: "tshark"}

    @os_supported(OSName.WINDOWS, OSName.LINUX, OSName.FREEBSD)
    def __init__(
        self,
        *,
        connection: "Connection",
        interface_name: str = "",
        absolute_path_to_binary_dir: "Path | str | None" = None,
    ):
        """
        Initialize Tshark.

        :param connection: mfd-connect object
        :param interface_name: name of the interface to use tshark on
        """
        super().__init__(connection=connection, absolute_path_to_binary_dir=absolute_path_to_binary_dir)
        self._interface_name = interface_name

    def _get_tool_exec_factory(self) -> str:
        """
        Get correct tool name.

        :return: Tool exec name
        """
        return self.tool_executable_name[self._connection.get_os_type()]

    def check_if_available(self) -> None:
        """
        Check if tool is available in system.

        :raises ToolNotAvailable when tool not available.
        """
        result = self._connection.execute_command(
            f"{self._tool_exec} -v", expected_return_codes=None, stderr_to_stdout=True
        )
        if "TShark (Wireshark)" not in result.stdout:
            raise ToolNotAvailable(returncode=1, cmd="tshark -v", output=result.stdout)

    def get_version(self) -> str:
        """
        Get Tshark version.

        :raises TsharkException when version not available.
        """
        result = self._connection.execute_command(
            f"{self._tool_exec} -v", expected_return_codes=None, stderr_to_stdout=True
        ).stdout
        version_regex = r"^TShark \(Wireshark\)\s(?P<version>.*)$"
        match = re.search(version_regex, result, re.M)
        if match:
            return match.group("version").rstrip()
        else:
            raise TsharkException("Version not found.")

    def start(self, *, capture_filters: str = "", filters: str = "", additional_args: str = "") -> "RemoteProcess":
        """
        Start TShark process with given filters and additional args.

        :param capture_filters: Capture filter expression (The syntax is defined by the pcap library).
        :param filters: Parameters that determine which network traffic should be captured.
        :param additional_args: Extra parameters that determine other options than filters.
        :return: Return connection process of run command.
        :raises TsharkException: if tshark command fails on execution
                                 if tshark incorrect args
                                 if interface_name was provided and another interface in filters
        """
        if self._interface_name and (
            re.search(r"-i |--interface ", filters) or re.search(r"-i |--interface ", capture_filters)
        ):
            raise TsharkException("Interface name was given twice, in interface_name and filters / capture_filters")

        command = f"{self._tool_exec}"
        if self._interface_name:
            command += f" -i {self._interface_name}"
        if capture_filters:
            command += f" -f '{capture_filters}'"
        if filters:
            command += f" {filters}"
        if additional_args:
            command += f" {additional_args}"

        try:
            process = self._connection.start_process(command=command, log_file=True, shell=True)
        except Exception as e:
            raise TsharkException("Problem with execution of tshark command.") from e

        self._validate_arguments_correctness(process)
        logger.log(level=log_levels.MODULE_DEBUG, msg="Started tshark.")
        return process

    def _stop_tshark(self, process: "RemoteProcess") -> None:
        process.stop(1)
        timeout = TimeoutCounter(5)
        while not timeout:
            if not process.running:
                return

    def _kill_tshark(self, process: "RemoteProcess") -> None:
        process.kill(1)
        timeout = TimeoutCounter(5)
        while not timeout:
            if not process.running:
                return

    def stop(self, process: "RemoteProcess", *, expected_output: bool) -> List[str]:
        """
        Stop tshark process and report result. Kill tshark process if after timeout is still running.

        :param process: OS process with tshark.
        :param expected_output: Decision if user expect to have output from command.
        :return: Output of tshark command sliced into list of str.
        :raises TsharkException: If process after stop and kill is still running.
                                 If process unexpectedly returned output.
                                 If process did not return output when expected.
        """
        if process.running:
            logger.log(level=log_levels.MODULE_DEBUG, msg="Stopping tshark process.")
            self._stop_tshark(process)
            # if process is still running, kill forcefully.
            if process.running:
                logger.log(level=log_levels.MODULE_DEBUG, msg="Killing tshark process.")
                self._kill_tshark(process)
                if process.running:
                    raise TsharkException("Problem with kill of tshark process")

        result = self._get_output(process)

        if result:
            if expected_output:
                return result.strip().splitlines()
            else:
                raise TsharkException("Tshark unexpectedly returned output!")
        else:
            if expected_output:
                raise TsharkException("Tshark did not return expected output!")
            else:
                return []

    def _validate_arguments_correctness(self, process: "RemoteProcess") -> None:
        """
        Check correctness of passed arguments after start of process.

        :param process: TSharkProcess
        :raises: TsharkException if passed incorrect args
        """
        timeout = TimeoutCounter(1)
        while not timeout:
            if not process.running:
                if any(
                    x in process.stderr_text.lower()
                    for x in {"invalid", "was not specified", "could not be initiated", "option requires an argument"}
                ):
                    raise TsharkException("Passed unsupported option as args.")
                else:
                    logger.log(level=log_levels.MODULE_DEBUG, msg=process.stdout_text)
                    raise TsharkException("TShark is not running.")

    def _get_output(self, process: "RemoteProcess") -> str:
        """
        Get tshark results from stopped tshark process.

        :param process: Process of connection object, necessary stopped tshark process.
        :return: Full output of tshark execution.
        :raises TsharkException: if process is running
        """
        if not process.running:
            if hasattr(process, "log_path") and process.log_path is not None:
                output = process.log_path.read_text(encoding="ISO-8859-1")
                if process.log_file_stream is not None:
                    process.log_file_stream.close()
                logger.log(level=log_levels.MODULE_DEBUG, msg=f"Removing {process.log_path} log file")
                p = self._connection.path(process.log_path)
                p.unlink()
            else:
                output = process.stdout_text
            return output
        else:
            raise TsharkException("Process is still running.")
