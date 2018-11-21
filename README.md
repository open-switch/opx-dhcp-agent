# opx-dhcp
This repository contains the OPX DHCP Agent files

- Data model is described through YANG
- API is accessed via CPS

The DHCP agent supports two modes of operation.

- Relay - acts as a conventional DHCP relay, inserts option 82 into the DHCP requests
- Switch Agent - transparently proxies DHCP requests and inserts option 82 into them

## Caveats - Before you start

ISC DHCP will always reply to the giaddr option set in the packet by the relay. While it knows the *actual* IP the request came from,
this information will not be used.

This results in a number of issues and limitations:

- The IP in the giaddr option must be reachable and be one of the addresses of the dhcp relay.
- ISC DHCP cannot support multiple subnets with the same addressing. If there is an address overlap on two different VLANs they have to be served by different ISC DHCP instances.

## Principles of operation

The agent relies on the fact that OPX VLANs are "backed" by linux bridges and any learned MACs show up in the bridge forwarding database (FDB). For relay mode operation the
interface on the switch should be in L3 mode, so the agent can see DHCP traffic without any additional configuration tweaks. For agent (man in the middle) mode, the agent adds
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

The optional file argument provides a configuration in json format from a file. If the file is specified, it will be reloaded each time the agent receives SIGHUP.
The agent will still register with CPS and respond to configuration requests via CPS even if the file is specified.

The configuration file should be a valid json representation of a list with elements in the form {"name":"interface name", "dhcp-server":"X.X.X.X"} or 
{"name":"interface name", "trusted":"trusted upstream port"}

Any interface with dhcp-server present is configured in relay mode. Any interface where the trusted attribute is present is configured in layer 2 (snooping) mode.

#### CPS Examples

##### Setup

1. Configure a vlan interace using the [VLAN application examples](https://github.com/open-switch/opx-docs/wiki/VLAN-application-examples).
2. The VLAN must have at least one port for Layer3/Relay mode and at least 2 ports for Layer2/Snooping mode.
3. For Layer3 mode, the vlan (br100) interface must have an ip address assigned. This can eb done either directly or using [IP address application examples](https://github.com/open-switch/opx-docs/wiki/IP-address-application-examples)
4. For Layer3 mode the subnet must be reachable from the DHCP server (as per the Caveats section above).

##### DHCP Agent application examples

The agent is a systemd service and will be started by the OpenSwitch runtime at boot time. 

It can also be run from the command line for debugging purposes - f.e. `./inocybe_dhcp/opx_dhcp.py --verbose 1`


```python
import cps
import cps_object
import cps_utils


# make our life easy by marking dhcp-server as an ip address attribute
cps_utils.add_attr_type('dhcp-agent/if/interfaces/interface/dhcp-server', 'ipv4')

cps_obj = cps_object.CPSObject('dhcp-agent/if/interfaces/interface')

cps_obj.add_attr("if/interfaces/interface/name","br100")

cps_obj.add_attr('dhcp-agent/if/interfaces/interface/dhcp-server',"192.168.3.1")

cps_update = {'change':cps_obj.get(),'operation': 'create'}

transaction = cps.transaction([cps_update])

```

This will set up the agent in relay mode on interface br100. It is now possible to query the result in cps as well.

Alternatively,

```python
import cps
import cps_object

cps_obj = cps_object.CPSObject('dhcp-agent/if/interfaces/interface')

cps_obj.add_attr("if/interfaces/interface/name","br100")

cps_obj.add_attr('dhcp-agent/if/interfaces/interface/trusted',"e101-001-0")

cps_update = {'change':cps_obj.get(),'operation': 'create'}

transaction = cps.transaction([cps_update])

```

Presently changes of interface type are *NOT SUPPORTED* - the relay agent config must be deleted before it is changed
from Layer 3 to Layer 2 and vice versa. Changing the ip address is supported. Full support for changes will be introduced
in later releases.

As a result of [CPS Issue 84](https://github.com/open-switch/opx-cps/issues/84) the relay agent config does not show up
as a proper augment when querying the interface in CPS. It can be accessed if it is addressed directly (as in the examples).

(c) 2018 Inocybe Technologies
