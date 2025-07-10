# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Module for exceptions."""

from mfd_base_tool.exceptions import ToolException


class TsharkException(Exception):
    """Handle Tshark tool exceptions."""


class TsharkExecutionError(ToolException, TsharkException):
    """Handle Tshark tool execution exceptions."""


class TcpdumpException(Exception):
    """Handle Tcpdump tool exceptions."""


class PktCapException(Exception):
    """Handle PktCap tool exceptions."""
