# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Packet Capture module: Pktcap."""

import logging
from typing import Optional, TYPE_CHECKING, List

from mfd_common_libs import add_logging_level, log_levels, os_supported
from mfd_base_tool import ToolTemplate
from mfd_base_tool.exceptions import ToolNotAvailable
from mfd_typing import OSName
from mfd_connect.exceptions import RemoteProcessTimeoutExpired

from mfd_packet_capture.exceptions import PktCapException

if TYPE_CHECKING:
    from mfd_connect import Connection
    from pathlib import Path
    from mfd_connect.process import RemoteProcess

logger = logging.getLogger(__name__)
add_logging_level("MODULE_DEBUG", log_levels.MODULE_DEBUG)


class PktCap(ToolTemplate):
    """Class for pktcap utility."""

    tool_executable_name = {OSName.ESXI: "pktcap-uw"}

    @os_supported(OSName.ESXI)
    def __init__(
        self,
        *,
        connection: "Connection",
        interface_name: str = "",
        absolute_path_to_binary_dir: "Path | str | None" = None,
    ):
        """
        Initialize PktCap.

        :param connection: mfd-connect object
        :param interface_name: name of the interface to use pktcap on
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
            f"{self._tool_exec} -h", expected_return_codes=None, stderr_to_stdout=True
        )

        if result.return_code != 0:
            raise ToolNotAvailable("Cannot find pktcap-uw tool on the system.")

    def get_version(self) -> str:
        """Get PktCap version."""
        return "N/A"

    def start(self, interface_name: Optional[str] = "", additional_args: Optional[str] = "") -> "RemoteProcess":
        """
        Start capturing packets using pktcap tool.

        :param interface_name: name of network interface
        :param additional_args: additional traffic parameters
        :raises PktCapException: if command fails on execution
                                if interface_name was provided on initialization and as start argument
        :return: Return connection process of run command.
        """
        if self._interface_name and interface_name:
            raise PktCapException("Interface name was given twice, on initialization and in start argument")

        command = (
            f"{self._tool_exec} --uplink "
            f"{interface_name if interface_name else self._interface_name}"
            f" {additional_args}"
        )
        logger.log(level=log_levels.MODULE_DEBUG, msg=f"Starting capturing packets via pktcap-uw. Command: {command}")
        try:
            return self._connection.start_process(command=command, stderr_to_stdout=True, log_file=True, shell=True)
        except Exception as e:
            raise PktCapException from e

    def _stop_pktcap(self, process: "RemoteProcess") -> None:
        try:
            process.stop(5)  # it will wait seconds for process to finish
        except RemoteProcessTimeoutExpired:
            return

    def _kill_pktcap(self, process: "RemoteProcess") -> None:
        try:
            process.kill(5)  # it will wait seconds for process to finish
        except RemoteProcessTimeoutExpired:
            return

    def stop(self, process: "RemoteProcess", *, expected_output: bool) -> List[str]:
        """
        Stop pktcap process and report result.

        :param process: pktcap-uw process handle
        :param expected_output: flag to determine if output is expected or not
        :raises PktCapException: if process after stop and kill is still running
        :raises PktCapException: if there is no output but expected_output is set to True
        :return: List of strings of stdout output
        """
        if process.running:
            logger.log(level=log_levels.MODULE_DEBUG, msg="Stopping pktcap-uw process.")
            self._stop_pktcap(process)
            # if process is still running, kill forcefully.
            if process.running:
                logger.log(level=log_levels.MODULE_DEBUG, msg="Killing pktcap-uw process.")
                self._kill_pktcap(process)
                if process.running:
                    raise PktCapException("Problem with kill of pktcap-uw process")

        if hasattr(process, "log_path") and process.log_path is not None:
            result = process.log_path.read_text(encoding="ISO-8859-1").splitlines()
            if process.log_file_stream is not None:
                process.log_file_stream.close()
            logger.log(level=log_levels.MODULE_DEBUG, msg=f"Removing {process.log_path} log file")
            p = self._connection.path(process.log_path)
            p.unlink()
        else:
            result = process.stdout_text.splitlines() if process.stdout_text else []

        if result:
            if expected_output:
                return result
            else:
                raise PktCapException("pktcap expectedly returned output, when it was not expected!")
        else:
            if expected_output:
                raise PktCapException("pktcap did not return the expected output!")
            else:
                return []
