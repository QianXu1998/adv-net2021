# AdvNet 2021 Project

---
**Important.** We may release some updates/bug fixes to the infrastructure files during the project.
If we do, the only thing you will have to do is run the following commands in the repository in your VM:

```bash
cd ~/p4-tools/infrastructure
git pull
cd ~/p4-tools/p4-utils/
git pull
```

:rotating_light: **Make sure you do this before every time you start working on the project.** :rotating_light:

---
---

On this page, you will find all key technical information about the AdvNet 2021 project, the network topology, and your task: reliably deliver as much traffic as possible for different traffic and failure scenarios.

> As announced at the beginning of the course, a group project will take place during second part of the semester. Quick reminder, this project counts for 40% of your final grade.

---

<!-- TOC depthTo:3 -->

- [Overview](#overview)
- [Timeline](#timeline)
- [Topology](#topology)
- [Programming your network](#programming-your-network)
    - [P4 code](#p4-code)
    - [Controller](#controller)
    - [Inputs](#inputs)
    - [Submitting your inputs](#submitting-your-inputs)
- [Running the simulation](#running-the-simulation)
    - [Network runner](#network-runner)
    - [Scenario timeline](#scenario-timeline)
- [Utilities (./cli.py)](#utilities-clipy)
    - [`./cli.py clean [path]`](#clipy-clean-path)
    - [`./cli.py monitor`](#clipy-monitor)
    - [`./cli.py set-opt-switch` and `./cli.py set-not-opt-switch`](#clipy-set-opt-switch-and-clipy-set-not-opt-switch)
    - [`./cli.py install-requirements [file]`](#clipy-install-requirements-file)
    - [`./cli.py get-delay [node1] [node2]`](#clipy-get-delay-node1-node2)
    - [`./cli.py experiment-performance [out-dir]`](#clipy-experiment-performance-out-dir)
- [Performance evaluation](#performance-evaluation)
- [Getting started](#getting-started)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)

<!-- /TOC -->

---

## Overview

The AdvNet 2021 project is a competition.
You and your team have full freedom to program your network to outperform the other teams!
The network topology is that of a real AS (the [Claranet network](https://noc.eu.clara.net/), shown below) and we consider all nodes to be P4-programmable switches.

> 🚨 **Important** 🚨
>
> The group ranking in the competition is _not_ taken into account in the final project grade. The project will be graded based on:
> - The interest of the solution;
> - The quality of the code;
> - The quality of the final presentations.
>
> More details will follow in due time.

<center>
<img src="figures/network.png" alt="project topology" width="600"/>
<p width="600">
The <a href="https://noc.eu.clara.net">Claranet network</a>; this is the network topology you will program in this year's project.
</p>
</center>

The network performance is measured as its ability to meet a number of service-level agreements (SLAs). These will be released in the first two weeks after the project begins and may include:

- Packet loss rate,
- Packet round-trip time,
- Flow completion time,
- Way-pointing (packets must traverse certain nodes).

Ultimately, all groups will be assessed on the same set of 1-minute long scenarios. Each scenario is defined by:

- The group's additional links (i.e., each group uses its own link configuration);
- The base traffic (that e will provide);
- One additional traffic, picked randomly among all the groups' configuration;
- One failure scenario, picked randomly among all the groups' configuration.

The groups will be ranked based on the number of SLAs that their network successfully meets (see [Performance evaluation](#performance-evaluation)).

## Timeline

The project ~~will start on week 7~~ starts on week 8; at this point, you will get access to new VMs for the project, and will be able to start programming your network.
The different SLAs and project features (additional links, additional traffic, failure scenarios) and SLA to fulfill will be made available progressively.

The most important dates are summarized below:

|||||
|---|---|---|---|
| ✅ |Week 8. | Tue, Nov.9 | Project starts - VMs are available|
| ✅ |Week 9. | Fri, Nov.19 **(tentative)** | All features available, and SLAs disclosed|
|  |Week 12.| Sun. Dec.12 **(changed!)**| Groups submit their traffic and failure configurations|
|  |Week 13.| Fri. Dec.17 | Groups submit their link configuration and switch programs|
|  |Week 14.| Mon. Dec.20 | Poster deadline|
|  |Week 14.| Tue. Dec.21 | Final presentation, disclosure of the competition results|

> The last exercise will take place on week 8. For the remaining weeks, the exercise sessions will be used as "project time" where teaching assistants will be available for technical support.

## Topology

In the project, each node in the Claranet topology (see above) is a single p4-enabled switch; the switches are interconnected as shown. In the following, we denote each switch by its label consisting of the first three letters of the respective city, e.g. `BAR` for the switch in Barcelona; we denote the links similarly, e.g. `BAR--MAD` for the link between Barcelona and Madrid.

All links between switches have a fixed bandwidth of 10 Mbps.
The link delay depends on the physical distance between cities; i.e., the farther apart cities are, the longer the delay of the link connecting them. The CLI provides a function (`./cli.py get-delay [node1] [node2]`) that returns the delay between any pair of switches (see below). Make sure you use this functionality when deciding which links to add to the topology.

Furthermore, each switch is connected to one host, labeled e.g., `BAR_h0` for the host in Barcelona. These hosts send and receive traffic. There are controlled by us (i.e., you cannot program them). The links between switches and hosts have no bandwidth limits and have no transmission delay. However, they still incur some small delay (~0.5ms).

As a general rule, we add `2.5ms` of delay for each 250km up to 2000km. Above 2000km, we set a fix delay of `25ms`.

|Link type|Bandwidth|Delay|
|---|---|---|
|Switch-Switch|10Mbps|Depends on distance; use: `./cli.py get-delay BAR MAD`|
|Host-Switch|No Limit|~0ms|


## Programming your network

The project task consists of programming your network devices---both the p4 data plane as well as the control plane---in order to fulfill a set of Service Level Agreements (SLAs).

As an input to the project you will have to provide a directory with three subdirectories (`p4src`, `controllers`, and `inputs`). For example, your initial input directory will look like:

```bash
├── controllers
│   ├── controller.py
│   └── requirements.txt
├── inputs
│   ├── test.failure
│   ├── test.links
│   ├── test.traffic-additional
│   └── test.traffic-base
├── p4src
│   ├── include
│   │   ├── headers.p4
│   │   └── parsers.p4
│   └── switch.p4
```

### P4 code

Place all your P4 code into the `p4src` directory.
Your starting point should be the file `p4src/switch.p4`.
This is the program installed on all switches by default.
If you want, you can override the program of individual switches using files named `<switch>-switch.p4`, e.g. `BAR-switch.p4`. Concretely, we use the following search order for each switch (using `BAR` as an example):

- Load an individual switch program (`BAR-switch.p4`) if it exists;
- Otherwise, load the default switch program (`switch.p4`).

> Note that different programs can share include files.

### Controller

You can put one (or multiple) controllers into the `controllers` directory.
We will start "all" (at most 16, i.e., one per switch) `controllers/*.py` files at the beginning of the simulation.
You _do not have to_ use more than a single controller, but are free to do so if you want.

The controller receives the base traffic as input, and can know which links were added by looking at the topology object. However, it will _not_ receive the additional traffic nor the link failures (see [Inputs](#inputs) below).
That means your controller can take the base traffic and added links for granted, but you need to detect/measure failures and additional traffic yourselves.
You will have several seconds of "start-up time" for the control logic to run and configure your network before any data-plane traffic is generated. This "start-up time" can be set using the main runner argument `--warmup`. See [Running the simulation](#running-the-simulation) for details.

> Note, switches have a cpu port. Thus, controllers are allowed to receive or send traffic from/to the switches.

> :rotating_light: Keep in mind that your code will be reviewed. Cheating using controller code is easy, but it's unlikely that we won't catch it when looking at your code...

### Inputs

We simulate traffic and failure scenarios to test your network.
Each scenario is defined by 4 inputs, found in the `inputs` directory:

- `<scenario>.traffic-base`: The basic traffic going through your network (specified by us, but you may play around with it to test your network).
- `<scenario>.traffic-additional`: Additional traffic that you specify, defined as fixed-rate UDP flows to be sent between chosen hosts for a given amount of time.
- `<scenario>.links`: Additional links that you can add to your topology.
- `<scenario>.failure`: Network failures that you specify, defined as failure start time and duration for specific links.
- **(NEW)** `<scenario>.slas`: Service Level Agreements (SLAs) that your network must fulfill.


> :rotating_light: __Important__ :rotating_light:  
The `test.traffic-base` file that we pushed in your GitLab repository _is not_ the final base traffic that will be used in the competition. The final base traffic will be released shortly. 

Note that we only specify the base traffic. You will be evaluated with the traffic and failures that you---and the other groups!---specify. Try to come up with scenarios that allow your network to shine while being challenging for the others!

Below, we detail the format and constraints on the traffic, links, and failure inputs.

#### Traffic

The traffic is defined using a _traffic matrix,_ specified as a `csv` file with the following format.

```text
src,    dst,    sport, dport, protocol, rate,  size, duration, start_time
BAR_h0, MAD_h0, 5000,  5001,  tcp,           , 10MB,         , 1
BAR_h0, LIS_h0, 5002,  5001,  udp,      1Mbps,     , 15,       10
```

- Each row in the matrix defines a single traffic flow between a `src` and a `dst` host, from `sport` port to the `dport` port.
- The protocol is either `tcp` or `udp`.
- For `tcp` flows, the matrix defines its start time (in seconds) and the total size of the traffic to transmit over that flow. The packet rate and flow duration will vary according to `tcp` dynamics.
- For `udp` flows, the matrix defines the packet transmission rate as well as the start time and flow duration (in seconds). Packets all have a fixed size of 1500 Bytes.

You must specify an additional traffic (`<scenario>.traffic-additional`) file as input for the evaluation scenario. You are free to specify this traffic as you wish, within the following constraints:

- UDP flows only;
- All traffic must start after `t=0` and end before `t=60`(in seconds);
- Start time and duration of the flows are integers (in seconds);
- Minimal flow duration is 1 second;
- Total number of Bytes sent over all flows is less than or equal 200 MB.\;
- The minimum flow rate is 100 Kbps;
- The maximum flow rate is 10 Mbps;
- The maximum number of flows overall is 1000 flows;
- All flows are using ports in the range `[60001, 65000]`.

For testing, you can also define base traffic (`<scenario>.traffic-base`) input files. You are free to specify this traffic as you wish, within the following constraints:

- UDP flows must start after `t=0` and end before `t=60`(in seconds);
- All flows are using ports in the range `[1, 60000]`;
- The maximum number of flows overall is 1000 flows.

#### Links

The additional links are defined using a `csv` file with the following format.

```text
src_switch, dst_switch, bw
BAR,        MUN,        10
LIS,        BER,        10
MAD,        FRA,        10
```

You are free to specify these links as you wish, within the following constraints:

- Only new links (i.e., you cannot duplicate an already existing link, such as `PAR--FRA`);
- You can add a maximum of 3 links.
- The bandwidth of each fixed is set to 10 Mbps.

#### Failures

The links to fail are defined using a `csv` file with the following format.

```text
src_switch, dst_switch, failure_time, duration
BAR,        MAD,        5,            1
LIS,        POR,        10,           5
LIS,        LON,        10,           10
ADDED_3,    ,           5,            10
```

The `src_switch` and `dst_switch` identify the link that is being failed. The failure start time and duration are in seconds.
Note that you can also fail the additional links (see above) by specifying `ADDED_{1,2,3}` in the `src_switch` column, leaving `dst_switch` empty, as shown above.

You must specify a failure file as input for the evaluation scenario. You are free to specify these failures as you wish, within the following constraints:

- No failure before `t=5` and after `t=50` (in seconds);
- Failures must not disconnect the network (without considering the additional links); for example, the `BRI--LON` cannot be failed, and `FRA--MUN` and `FRA--BER` cannot be failed simultaneously;
- The total duration of all failures is at most 30 seconds.

> Note: to know if your failure scenario disconnects the network you can simply run it. If the scenario is not valid you will get an error message indicating so.

#### SLAs

> 🚨 **Updates** 🚨  
The `prr` SLA's target is now specified in ratio (used to be in percent), and the times are specified in seconds. This is to be consistent with the outputs from the measurement script.  
We also removed the `rtt` SLA, which will not be used in this year's project.  
Finally, we use SLA types of `prr` and `fcr` for UDP and TCP flows, respectively. Again, this is to be consistent with the outputs from the measurement script.  

The SLAs are defined using a `csv` file with the following format (below are only examples, not actual SLAs to satisfy).

```
id        , src   , dst   , sport      , dport      , protocol  , type  , target
prr_0     , *     , *     , *          , *          , udp       , prr   , 0.5
fcr_0     , *     , *     , *          , *          , tcp       , fcr   , 1
fct_0     , BAR_h0, MAD_h0, 5000--*    , 5000--5010 , tcp       , fct   , 1.5
delay_0   , BAR_h0, MAD_h0,    *--5001 , 5010--5020 , udp       , delay , 50
wp_0      , BAR_h0, MAD_h0, 5001--5010 , 5000--5010 , *         , wp    , PAR
```

where `*` signifies a wildcard. Ports may be specified as concrete values, e.g.
`5000` or `*`; or ranges (wildcards possible), like `5000--5010` pr `5000--*`.

There are four different types of SLAs:

- `prr`: Packet Reception Ratio. The target value defines the ratio of packets sent that must have reached the destination by the end of the test. A value of `1` indicates that all packets must be received. For UDP flows only.
- `fcr`: Flow Completion Ratio. The target value defines the ratio of packets sent that must have reached the destination by the end of the test. A value of `1` indicates that all packets must be received. For TCP flows only.
- `fct`: Flow Completion Time. The target value defines the upper-bound for the completion time for receiving all packets from a flow. For to TCP flows only.
- `delay`: Delay. The target value defines the upper-bound for the mean delay for receiving each packet from a flow. For UDP flows only.
- `wp`: Way-pointing. The target value defines one switch that _all packets_ from a flow must traverse before reaching their destination.

By definition, the `fct` of a TCP flow is undefined (returns `None`) unless the `fcr` of that flow is `1`.

> 🚨 **Important** 🚨  
Most SLAs match multiple flows. For an SLA to count as "met," _all matching flows_ must reach or do better than the target value (i.e., higher `prr` or lower `delay`/`fct`). Yes, it's hard :slightly_smiling_face:

Naturally, the `fct` and `delay` SLAs are not considered "met" if no packet reach their intended destination. More precisely, at least one packet of each flow matching a `delay` SLA must be successfully received for that SLA to be satisfiable.

### Submitting your inputs

Good news: you have (almost) notion to do! :smiley:

Once per day, we will fetch your input files directly from your repositories and use them to test your network configuration. The only requirement is that your input files are located in the `/inputs` folder and named:

- `group.failure`
- `group.links`
- `group.traffic-additional`

The `.failure` and `.traffic-additional` inputs will be pushed into this public repository:
https://gitlab.ethz.ch/nsg/public/adv-net-2021-project-inputpool

<!-- > TODO: add this as a submodule in the student repo? We could add that as a comment like: they can do it if they want... Low-prio task. -->

This allows you to test your own network configuration with the inputs provided by the other groups.

## Running the simulation

### Network runner

We have pre-installed a set of utils in your VMs that can be used to run and test your network scenarios. The [main runner script](./run.py) can be found at `~/p4-tools/infrastructure/`. This script is very similar to the one you have used during the exercises, however this time it is in charge of running the entire pipeline; from parsing input files and schedule link events, to generate the traffic and store all the collected metrics into output files.

To run the network, you can simply run:

```bash
sudo python run.py --inputdir <path to inputs> --scenario test
```

This command, will take your inputs, create the network, generate traffic, and block the program until all the traffic has been sent. If you want to be able to access the `mininet` CLI as you used to in the exercises, you must use the `debug-mode` option:

```bash
sudo python run.py --inputdir <path to inputs> --debug-mode --scenario test
```

For example, allowing you to run connectivity tests using `pingall`:

```
*** Starting CLI:
mininet> pingall
*** Ping: testing ping reachability
AMS_h0 -> BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
BAR_h0 -> AMS_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
BER_h0 -> AMS_h0 BAR_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
BRI_h0 -> AMS_h0 BAR_h0 BER_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
EIN_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
FRA_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
GLO_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
LIL_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
LIS_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
LON_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
MAD_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
MAN_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MUN_h0 PAR_h0 POR_h0 REN_h0
MUN_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 PAR_h0 POR_h0 REN_h0
PAR_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 POR_h0 REN_h0
POR_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 REN_h0
REN_h0 -> AMS_h0 BAR_h0 BER_h0 BRI_h0 EIN_h0 FRA_h0 GLO_h0 LIL_h0 LIS_h0 LON_h0 MAD_h0 MAN_h0 MUN_h0 PAR_h0 POR_h0
*** Results: 0% dropped (240/240 received)
mininet>
```

Use `-h` to see all the command line parameters.

```bash
usage: run.py [-h] [--inputdir INPUTDIR] [--scenario SCENARIO]
              [--warmup WARMUP] [--outputdir OUTPUTDIR] [--debug-mode]
              [--log-enabled] [--pcap-enabled] [--no-events] [--no-constrains]
              [--check-inputs]

optional arguments:
  -h, --help            show this help message and exit
  --inputdir INPUTDIR   Path to all inputs (controllers, p4src)
  --scenario SCENARIO   Path to all input events (links, failures, traffic)
  --warmup WARMUP       Time before starting the simulation
  --outputdir OUTPUTDIR
                        Path were the experiment outputs will be saved. If it
                        exists, all content is erased
  --debug-mode          Runs topology indefinitely and lets you access the
                        mininet cli
  --log-enabled         Enables logging
  --pcap-enabled        Enables pcap captures (not recommended)
  --no-events           Disables all link and traffic events. Useful for
                        debugging.
  --no-constrains       Disables traffic and link constrains (only use for
                        testing).
  --check-inputs        Only checks if input files fulfill the constrains. Does
                        not run the network!
```

> :rotating_light: We do not recommend enabling pcap captures. It might have a big impact on the experiment's performance, and it could make your VM run out of hard disk very quickly. Thus, use with care! :rotating_light:

### Scenario timeline

By default each simulation last for about 85 seconds (when not run in `debug-mode`). This is decomposed into:

- **20s of start-up time**, which are used to spin up the simulation, configure your network, start the host processes, etc. You can exchange control messages during this time (e.g., to signal MPLS tunnels) but no data plane traffic is generated. You can set this time to something smaller if you want using `--warmup`, however, keep in mind, that for the real evaluation we will use 20 seconds.
- **60s of event generation**, during which data plane traffic is generated and links fail.
- **5s of closing time**, which are used to finish the collection of packets remaining in-transit.
Every packet remaining in the network after this time elapses is counted as lost.

The `t=0` time correspond to the start of the _event generation phase_. In other words, the time span of one simulation is `[-20s; 65s]`.


## Utilities (./cli.py)

On top of the main network runner, we provide you with a set of very handy utilities. You can see the list of all cli commands below.

```bash
Usage: ./cli.py COMMAND [ARGS...]

Commands:
=========
help                           Shows the help menu.
clean [path]                   Cleans a working P4 directory.
monitor                        Print the bit rate of each link in real time.
set-opt-switch                 Enables optimized P4 switch.
set-non-opt-switch             Enables debugging P4 switch.
install-requirements [file]    Install python requirements for [file]
get-delay [node1] [node2]      Prints delay between two cities.
experiment-performance [path]  Prints every flow performance in [path]
```

> Note: `experiment-performance` is not yet implemented. 

### `./cli.py clean [path]`

Simple command that can be used to recursively clean a directory where a network has been run. It basically cleans:
1. Log directories.
2. Pcap directories.
3. P4 compile outputs.

### `./cli.py monitor`

With multiple flows and failures, it can be cumbersome to track what is going on.
We have prepared a monitoring command that displays the current link load for all links in real-time.

The command displays the bit rate for both directions of a link.
For the left to right direction, the bit rate is shown on the left-side;
for the right to left direction, the bit rate is shown on the right-side.
If a link is strictly vertical, the bit rate for the top to bottom direction is shown on the left-side, and the bit rate for the bottom to top direction is shown on the right-side.

> Make sure your terminal is high and wide enough to fit the whole display!

### `./cli.py set-opt-switch` and `./cli.py set-not-opt-switch`

The VMs come with two pre-compiled versions of the software switch. One has been
compiled with optimization flags, and the other with debug flags. You can
easily switch between one or the other by using this command line.

In general, given the size of the topology and amount of traffic generated, we
highly recommend you to use the `optimized` version by default. Thus, only use
the `non-opt` version when you really need to look at the low-level P4 debugger.

### `./cli.py install-requirements [file]`

Installs all controller requirements found in file. When running your solution,
we will make sure to install the requirements found in
`inputs/controllers/requirements.txt`.

### `./cli.py get-delay [node1] [node2]`

Prints the one way delay between two cities in the topology. You can use it to
see the delay of existing links, or links you want to add. For example:

```
> ./cli.py get-delay BAR MAD
> The delay between BAR and MAD is : 5.0ms

> /cli.py get-delay BAR BER
> The delay between BAR and BER is : 15.0ms
```

### `./cli.py experiment-performance [out-dir]`

Prints the individual performance of each flow. Separated by `udp` and `tcp`. 

For `UDP` traffic we measure the packet reception rate in percentage. A 1 means, 100% of the packets where received, whereas 0 means 0% reception rate. For the second parameter, we print the average one way delay. Finally, in the third column, you will find the waypoint rate. The waypoint rate, is the fraction of packets that have been received and have crossed the waypoint switch. If the flow does not have any waypoint rule, we simply display `-`.

For `TCP` traffic we measure three things. First the completion rate, which is the percentage of total received bytes. Second, the average flow RTT, and last, the flow completion time in seconds.

```bash
./cli.py experiment-performance ./outputs/

----------------------------------
Experiment performance: ./outputs/
----------------------------------

-----------------------------------------------------------------------------------
UDP Flow                            Reception Rate    Avg Delay     Waypoint Rate
-----------------------------------------------------------------------------------
BAR_h0  MAD_h0   60001 60001             1.0            0.0055            -
BAR_h0  MAD_h0    3000  3000             1.0            0.0055           0.0
BAR_h0  MAD_h0     500    10             1.0            0.0054           0.0
AMS_h0  MUN_h0    1000  1000             1.0            0.0056           1.0
POR_h0  BAR_h0     200    50             1.0            0.0108           1.0
BAR_h0  MAD_h0    5002  5003             1.0            0.0054           0.0
BAR_h0  MAD_h0     501    11             1.0            0.0055           0.0

-----------------------------------------------------------------------------------
TCP Flow                           Completion Rate     Avg RTT           FCT
-----------------------------------------------------------------------------------
LIS_h0  POR_h0    5000  5001             1.0            0.038          0.900295
```

>  Note that in the latest version, the experiment performance will automatically be displayed at the end of your run (unless you run with `--debug-mode` flag).

> Note if you run in `--debug-mode` make sure you stop the network before you check the performances. Some files are only flushed when the network is stopped. If not, the tool might report incomplete results.

## Performance evaluation

In each run of the simulation, we collect various information (delay, packet reception, etc.) required to assess whether the various SLA are met. 

> Ultimately, the simulation runner will directly compute and return which SLAs your network satisfies. This will be released soon.

<!-- The simulation directly outputs which SLAs your network satisfies. -->

The SLA to satisfied are listed ~~in `/project/SLA.txt`~~ in `/inputs/<scenario>.slas`. See [SLAs](#slas) for the SLA formatting.

In the final evaluation, the networks of the different groups will be compared based on the number of SLA they satisfy; each SLA satisfied collects points, but satisfying "harder" SLAs brings more points, where "hard" is defined by the number of groups that failed to meet a specific SLA. More concretely, the number of points `p` given by satisfying SLA `s` is:

<img src="https://render.githubusercontent.com/render/math?math=p%20=%201%20%2B%20\sum_{i%20\text{,%20}%20g_i%20\nvDash%20s}1">

> That is, one point plus one per group that failed to satisfy the SLA.

Soon after the project start, we will perform this evaluation on one randomly selected scenario every day, and push the results on a public leaderboard.
This will allow:

- Us to monitor your progress, and
- You to know how you (currently) fare compared to the other groups.

The final competition will consider a set of scenarios (exact number to be confirmed) using different traffic and failure inputs randomly selected from the [input pool](https://gitlab.ethz.ch/nsg/public/adv-net-2021-project-inputpool). Points are summed over all scenarios; the group with the most points wins.

## Getting started

You should have received credential to connect to your project VM, as well as access to a private GitLab repository, e.g., https://gitlab.ethz.ch/nsg/lectures/lec_advnet/projects/2021/14_allen

> If you don't have one of these, please let us know asap.

To get started, log in your project VM, clone your GitLab repository, and you are good to go to start coding :smiley:

The list of SLA to satisfy will be added shortly.

## Frequently Asked Questions (FAQ)

Moved in [a dedicated page](FAQ.md)