# Frequently Asked Questions (FAQs)

<!-- TOC -->

- [Allowed / Not allowed](#allowed--not-allowed)
    - [What modifications are we allowed to do on the packets?](#what-modifications-are-we-allowed-to-do-on-the-packets)
    - [Is it allowed to use the controller to "teleport" packets between different switches?](#is-it-allowed-to-use-the-controller-to-teleport-packets-between-different-switches)
    - [What am I allowed to do in the controller?](#what-am-i-allowed-to-do-in-the-controller)
- [About SLAs](#about-slas)
    - [How to "meet" an SLA that applies to multiple flows?](#how-to-meet-an-sla-that-applies-to-multiple-flows)
    - [Does loosing a packet in a TCP flow prevents from meeting a `fcr=1` SLA?](#does-loosing-a-packet-in-a-tcp-flow-prevents-from-meeting-a-fcr1-sla)
    - [(Clarified) Is it allowed to generate additional traffic for the flows that must be way-pointed?](#clarified-is-it-allowed-to-generate-additional-traffic-for-the-flows-that-must-be-way-pointed)
    - [(NEW) Can packets be duplicated in order to meet the way-pointing SLAs?](#new-can-packets-be-duplicated-in-order-to-meet-the-way-pointing-slas)
- [Development, tooling, debugging](#development-tooling-debugging)
    - [How to run the project on my own machine?](#how-to-run-the-project-on-my-own-machine)
    - [How can we implement queuing?](#how-can-we-implement-queuing)
    - [(NEW) Can we use queueing metadata in the switch?](#can-we-use-queueing-metadata-in-the-switch)
    - [Why do UDP flows seem to randomly lose a few packets?](#why-do-udp-flows-seem-to-randomly-lose-a-few-packets)
    - [How to interpret the output of `./cli.py experiment-performance [output-dir]`?](#how-to-interpret-the-output-of-clipy-experiment-performance-output-dir)
    - [Is there a way to get topology link delays other than using the `cli`?](#is-there-a-way-to-get-topology-link-delays-other-than-using-the-cli)
    - [How come my delay/rtt is higher than expected? (IMPORTANT)](#how-come-my-delayrtt-is-higher-than-expected-important)
- [About the final presentation/evaluation](#about-the-final-presentationevaluation)
    - [Will we have to print an actual poster for the final presentation?](#will-we-have-to-print-an-actual-poster-for-the-final-presentation)

<!-- /TOC -->

<!-- ##################################################### -->

## Allowed / Not allowed

### What modifications are we allowed to do on the packets?

You are allowed to modify, add, or remove regular packets' header fields for most of the traffic (with one exception, see below). However, it is **forbidden to touch the packets' payload** in any way. For example, you cannot simply drop the payload to reduce size of the traffic, neither are you allowed to "compress it" somehow. You are simply not allowed to alter the payload bytes in any way. We consider as "payload" all the bytes that come after the transport layer protocol headers.  

If needed, you are allowed to add new headers _between_ the transport layer and the payload, as long as packets  received by receivers are compliant to the network stack at the host nodes; that is, they must be reconstructed in their orginal format before sending to the destination host.

**Important.** For traffic that has to be way-pointed, there are additional limitations:

- The packet headers must be of the form: `ethernet + mpls + ip` or `ethernet + ip`. If they do not
  follow this pattern, we won't be able to verify the waypoint policy for them. If you use `mpls`,
  use the one we saw in RSVP exercise (stacked version, with 4 bytes per label). We parse a max of
  10 Labels. 
- You must keep the following header fields untouched (i.e., keep the original ones):
  - Ethernet type (`0x0800` or `0x8847`)
  - IP source address.
  - IP destination address.
  - IP TOS field.

To rephrase: For the traffic to be correctly measured as way-pointed, you must follow one of these two header formats, you must not change the values of four specific fields, and you must not delete the other header fields.

This is only for way-pointing; the other SLA types are not impacted.

> If you do not follow these rules, your traffic will not be counted as way-pointed, and you will not get any points for those SLAs.

### Is it allowed to use the controller to "teleport" packets between different switches?

No. As explained [below](#what-am-i-allowed-to-do-in-the-controller) you can not send traffic from a given switch and send and then inject it a different switch.

### What am I allowed to do in the controller?

You are allowed to run anything in the controller as long as you only interact with the network as follows:

- Configure switches through the controller API.
- Receive Packets from the switch.
- Send additional packets to the switch.

Thus, you can not do things like:

- Run commands that might modify the state or configuration of the network.
- Run commands that allow you to monitor the state of the network. For example, continuously checking which interfaces are `up` to detect link failures is not allowed.
- You can not receive real traffic from one switch and send it to another. For example, `BAR` sends packets to the controller, and the controller injects them to another switch to bypass the network.

<!-- ##################################################### -->

## About SLAs

### How to "meet" an SLA that applies to multiple flows?

For an SLA to count as "met," _all matching flows_ must reach or do better than the target value (i.e., higher `prr` or lower `delay`/`fct`). Yes, it's hard :slightly_smiling_face:

### Does loosing a packet in a TCP flow prevents from meeting a `fcr=1` SLA?

No, as long as (at least) one retransmission of this packet reaches its destination before the end of the test.

> Note that this is true for UDP and `prr` SLA's as well. You could implement a reliable transport scheme to retransmit lost UDP packets (if you feel like it's worth it).

We only look at the packet reception at the end of the test.

### (Clarified) Is it allowed to generate additional traffic for the flows that must be way-pointed?

In other words: Are we allowed to provide additional traffic that matches an SLA?

Yes. If the additional flows you specify match an SLA (currently, that is possible for way-pointing only), then the SLA has to be met for these flows as well.

### (NEW) Can packets be duplicated in order to meet the way-pointing SLAs?

No, the way-pointed packets must be the original ones.

For example, it is forbidden to clone a packet that must be way-pointed, send one copy directly to the destination, and send the other copy to the way-point then drop it there.

Packets from `A` to `B` that must be way-pointed via `C` _must_ follow a path of the form `A->C->B`.

<!-- ##################################################### -->

## Development, tooling, debugging

### How to run the project on my own machine?

Some of you asked for a way to work in parallel during the project. To make that easier, we have uploaded a VirtualBox Virtual Disk Image. You can download it here:

- URL: https://polybox.ethz.ch/index.php/s/IHVIURpTts4kF8C 
- Password : `adv-net-2021`

For this to work you must use VirtualBox (try to update to the latest version, I had problems until I did that). To set up the VM, do the following:

- Create a new VM
- Go to expert mode
- Name it, select type Linux and version Ubuntu 64 bits
- Set memory (at least 4GB)
- For hard disk, use an existing virtual hard disk file. Here select the disk image you downloaded.

The VM user and password are both `p4`.

### How can we implement queuing?

Unfortunately, the implementation of multiple queues in the `bmv2` software switch are... unreliable (it's an under-statement). Therefore, we have disabled them in the project, such that you don't run into problems that have nothing to do with your own configuration.

> That's not great, we know, but there is not much we can do about it...

There is one alternative you can use to implement some queuing logic in your network nonetheless: you can send traffic to the controller, and implement buffer management and queuing there (if you find it to be worth it since this might further increase delay on packets).

### Can we use queueing metadata in the switch?

The `bmv2` p4 model exposes queueing metadata such as `enq_qdepth`, `deq_timedelta` and `deq_qdepth`, but they contain essentially useless values in our project and you should not rely on them for your solution.

We use linux `tc` to rate limit the links (i.e 10 Mbps) and add some delay. This happens after the packet leaves 
the switch -- which means that all congestion and buffering happens _outside_ of the switch, and the switch queue never contains more than a single packet.
Thus, the queueing metadata does not provide you with any useful information about the actual congestion on a link.


### Why do UDP flows seem to randomly lose a few packets?

If you do tests with a single UDP flow, and 0 congestion, you will see that sometimes the reported `prr` is a bit below 1 (1-3 packets get lost). In short, this is a problem in the `bmv2` switch model that we use for simulation. We could not pinpoint the reason for it at the point.

> This is why updated the list of SLAs with a maximum `prr` target of 99% for UDP flows. As this glitch loose only very few packets, it will not cause 1% packet loss for our scenario; 99% is actually a quite generous for a "perfect" flow.

### How to interpret the output of `./cli.py experiment-performance [output-dir]`?

You can find a detailed explanation [here](README.md#clipy-experiment-performance-out-dir).

### Is there a way to get topology link delays other than using the `cli`?

Yes, you can use the `Delay` class of [get_city_info.py](advnet_utils/advnet_utils/get_city_info.py). For example in your controller you can do:

```python
from advnet_utils.get_city_info import Delay
_delay = Delay(<path to project folder>) # infrastructure/project/
delay = _delay.get_delay("BAR", "PAR")
```

> The project folder, is not the infrastructure folder itself, but the folder called `project` inside `/home/p4/infrastructure`

> Note this returns the delay of a directly connected link. The delay with multiple hops is the sum of the individual delays + queueing times + switch processing time.

### How come my delay/rtt is higher than expected? (IMPORTANT)

The delay we set to each link represents only the propagation delay (time for a signal to propagate through the media usually a bit lower than speed of light).

To that you need to sum three more things:

- `Processing delay`: the time it takes for your software switch to process the packet. And since we are using a software switch, the more complex the code is the more time it will take.
- `Transmission delay`: time it takes to push a packet into the link. In our case, this is not negligible. To transmit a 1500 bytes packet at 10Mbps we need `1.2ms`((1500*8)/10000000).
- `Queueing delay`: the time a packet spends in the interface queues. We have set interface queues to 100 packets. That means, that for every packet of 1500 in the queue, packets experience an extra 1.2ms of delay. If the queue is completely full (under heavy congestion) the queuing delay will be `120ms`!.

As you can see, queuing delay plays a huge role in the total delay your traffic might experience. Therefore, when having to optimize for delay/rtt make sure your queues don't build up. For example, if you send 2 `udp` flows to the same link, and their total bandwidth accounts for more than 10Mbps, unless you start dropping something, the queue will eventually get full and all packets will experience an additional 120ms delay.

Furthermore, and also interestingly, you can observe, that by sending a single `tcp` flow, queues will build for some packets. This is due to how `tcp` works. If there is no congestion in the network, once a flow reaches a sending rate of `10Mbps` it continues growing, that makes the queue to grow and delay increases until there is a drop and `tcp` slows down.

<!-- ##################################################### -->

## About the final presentation/evaluation

### Will we have to print an actual poster for the final presentation?

This remains to be decided, as it will depend on whether we can hold the final session in person, or not. Updates on the final presentation format will follow in due time.

<!-- ##################################################### -->
