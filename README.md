> [!IMPORTANT] 
> This project is under development. All source code and features on the main branch are for the purpose of testing or evaluation and not production ready.

# MFD Packet Capture

Module for Packet Capture support, module implements [mfd-base-tool](https://github.com/intel/mfd-tool).
Within the module, there are wrappers written for tcpdump, tshark & pktcap tools.

## OS supported:
* WINDOWS (tshark)
* FREEBSD (tshark)
* LINUX (tcpdump, tshark)
* ESXI (tcpdump, pktcap)

## Tshark Usage

```python
from mfd_packet_capture import Tshark
from mfd_connect import RPyCConnection

# establish connection via mfd-connect
connection = RPyCConnection(ip="10.10.10.10")
tshark = Tshark(connection=connection, absolute_path_to_binary_dir = "C:\\tshark\\", interface_name="eth0")
version = tshark.get_version()
tshark_process = tshark.start()
time.sleep(2)
result = tshark.stop(tshark_process, expected_output=True)
```

For Windows pass network interface in quote, e.g.:
```python
tshark_process = tshark.start(filters='-i "Ethernet 2"', additional_args="-l")
```
### API documentation

- `Tshark(connection: Connection, interface_name: str = "", absolute_path_to_binary_dir: "Path | str | None" = None` - Initializes Tshark instance on given connection and optionally interface name. If `interface_name` is not given on initialization, it can be passed through `tshark.start(filters="-i interface_name")` 

- `start(*, capture_filters: str = "", filters: str = "", additional_args: str = "") -> "RemoteProcess"` - Start TShark process with given filters and additional args.\
Capture filters will be passed with `-f` param to TShark.\
Raises `TsharkException` if tshark command fails on execution, if passed incorrect args or if interface_name was defined and another interface is passed in `tshark.start(filters)`

- `stop(process: "RemoteProcess", *, expected_output: bool) -> List[str]` -  Stop tshark process and report result.
raises `TsharkException`: If process after stop and kill is still running or
                        unexpectedly returned output or
                        does not returned output when expected.

## Tcpdump Usage
```python
from mfd_packet_capture import Tcpdump
from mfd_connect import RPyCConnection

# establish connection via mfd-connect
connection = RPyCConnection(ip="10.10.10.10")
tcpdump = Tcpdump(connection=connection, interface_name="eth0")
version = tcpdump.get_version()
tcpdump_process = tcpdump.start(additional_args="-l")
time.sleep(2)
result = tcpdump.stop(tcpdump_process, expected_output=True)
```

### API Documentation

- `Tcpdump(connection: Connection, interface_name: str = "", absolute_path_to_binary_dir: "Path | str | None" = None` - Initializes Tcpdump instance on given connection and optionally interface name. If `interface_name` is not given on initialization, it can be passed through `tcpdump.start(filters="-i interface_name")` 

- `start(*, filters: str = "", additional_args: str = "", namespace: str | None = None) -> "RemoteProcess"` - Start Tcpdump process with given filters and additional args.
Raises `TcpdumpException` if tcpdump command fails on execution, if passed incorrect args or if interface_name was defined and another interface is passed in `tcpdump.start(filters)`

- `stop(process: "RemoteProcess", *, expected_output: bool) -> List[str]` -  Stop tcpdump process and report result.
Raises `TcpdumpException`: If process after stop and kill is still running or
                        unexpectedly returned output or
                        did not return output when expected.

- `read_tcpdump_packets(file_path: Path, additional_args: str="-nvv", namespace: str | None = None) -> list[str]` - Read packets from file which was created with other tools e.g pktcap-uw in pcap or pcapng format.
Raises `TcpdumpException`: If given `file_path` was not found


## PktCap usage

```python
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
```

### API Documentation

- `PktCap(connection: Connection, interface_name: str = "", absolute_path_to_binary_dir: "Path | str | None" = None` - Initializes PktCap instance on given connection and optionally interface name. If `interface_name` is not given on initialization, it can be passed through `pktcap.start(interface_name="interface_name")`

- `start(interface_name: str, additional_args: Optional[str] = "") -> RemoteProcess` : to start capturing packets via pktcap-uw.
Raises `PktCapException` if command fails on execution or if interface name was given both on initialization and as `start()` argument. 
- `stop(process: RemoteProcess, *, expected_output: bool) -> List[str]` : stop pktcap-uw process and get its output (combined stdout & stderr).
Raises `PktCapException` if process after stop and kill is still running or if there is no output but expected_output is set to True.

If you encounter any bugs or have suggestions for improvements, you're welcome to contribute directly or open an issue [here](https://github.com/intel/mfd-packet-capture/issues).
