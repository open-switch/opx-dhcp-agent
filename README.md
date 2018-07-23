# opx-dhcp
This repository contains the OPX DHCP Agent files

- Data model is described through YANG
- API is accessed via CPS

The DHCP agent supports two modes of operation.

- Relay - acts as a conventional DHCP relay, inserts option 82 into the DHCP requests
- Switch Agent - transparently proxies DHCP requests and inserts option 82 into them

## Principles of operation

The agent relies on the fact that OPX VLANs are "backed" by linux bridges and any learned MACs show up in the bridge forwarding database (FDB). For relay mode operation the
interface on the switch is in L3 mode, so the agent can see DHCP traffic without any additional configuration tweaks. For agent (man in the middle) mode, the agent adds
filter rules which drop all DHCP packets while copying it to "CPU". As a result DHCP packet shows up on the backing linux bridge and creates a FDB entry which can be read
to supply option 82 information. As a side effect, these rules will also prohibit the operation of any unauthorized DHCP servers - they can be operated only on the trusted
port.

For underlying NAS and SAI implementations where drop+copy-tocpu is not possible the agent needs to use an alternative FDB search library. 

The DHCP Agent supports only basic operation and Option 82 SubType 1 insertion in this release. Future releases will add support for arbitrary "changes" and "adjustments" to the DHCP packets in addition to
basic relay and agent/Option 82 functionality.

## API documentation
The Agent API is documented in the Yang model.

## Packages

TODO

### dhcp\_agent.py
Invokes the agent. Unless mock test/mode is specified the agent will register with CPS and expect configuration from CPS.

#### Usage

`opx_dhcp.py [--verbose] [--file json_configuration.json] `

Specifying the optional file argument prevents dhcp from registering with CPS and enables the optional mock mode. In mock
mode configuration is read in json format from a file and reloaded each time the agent receives SIGUSR1.

The configuration file should be a valid json representation of a list with elements in the form {"name":"interface name", "dhcp-server":"X.X.X.X"} or 
{"name":"interface name", "trusted":"trusted upstream port"}

Any interface with dhcp-server present is configured in relay mode. Any interface with the trusted attribute present is configured

(c) 2018 Inocybe Technologies
