## Group info

| 04_cerf | XYZ |  |  |
| --- | --- | --- | --- |
| Member 1 | Ziqiao Kong| zikong | zikong@ethz.ch |
| Member 2 | Jiantao Liu | jianliu | jianliu@ethz.ch |

## Overview

The goal of our network is to make the full use of every link while trying to meet as many SLAs as we can. The main motivation of our solution is "dynamic routing driven by real time statistics". Therefore, our solution could be splitted by two parts: the statistic and the dynamic (re)routing.

### Collecting Realtime Data

To make the (re)routing decision, we have to collect the real time flows and performance of our network. This is achieved by several monitors.

#### Ping-Pong Monitor

Ping-Pong monitor, literally, is used to monitor whether a link is failed by sending hello messages to each other. The most code is re-used from exercise session, except that the failure state is passed to controller not by the digest but by the controller API.

#### Flows Monitor

To have a better granularity of dynamic routing, we also implement a flow monitor with `scapy`. The implementation is quite straightforward, we sniff the 16 switch interfaces which are connected to the host and resolve the TCP and UDP flows. 

### Dynamic Routing Decision

#### MPLS

The basic routing mechanism is MPLS, which provides us with the max flexibility.

#### Dynamic Re-routing

If we detect a failure or a link overload, we would do a re-routing based on the realtime information we know. Also, we setup LFA for each failed link so the packets sent before a failure can also reach its destination.

#### Meter

To fullfill more SLAs, we restrict some traffic with meters and drop some traffic we can't handle.

## Individual Contributions

### Ziqiao Kong

- MPLS implementation.
- Monitor design and implementation.
- Re-routing implementation.

### Jiantao Liu

- LFA Implementation.
- Testing with different inputs.