"""SLA verification.

# Input files

The SLA file is expected to have at least the following columns (more are
possible, but ignored): (the rows are examples)

```
id        , src   , dst   , sport      , dport      , protocol, type, target
prr_0     , *     , *     , *          , *          , *  , prr   , 50
fct_0     , BAR_h0, MAD_h0, 5000--*    , 5000--5010 , tcp, fct   , 1000
delay_0   , BAR_h0, MAD_h0,    *--5001 , 5010--5020 , udp, delay , 50
rtt_0     , BAR_h0, *     , 5000--5010 , 5000--5010 , tcp, rtt   , 100
wp_0      , BAR_h0, MAD_h0, 5001--5010 , 5000--5010 , *  , wp    , PAR
```

where `*` signifies a wildcard. Ports may be specified as concrete values, e.g.
`5000` or `*`; or ranges (wildcards possible), like `5000--5010` pr `5000--*`.

The result file expects the following columns: (rows are examples)

```
src,dst,sport,dport,protocol,prr,delay,rtt,fct
BAR_h0,MAN_h0,5001,5001,udp,0.9993718592964824,0.11126276114539932,,
BAR_h0,LIS_h0,5002,5001,udp,0.9996859296482412,0.13034784026090507,,
BAR_h0,MAD_h0,5000,5001,udp,1.0,0.005361837320890858,,
BAR_h0,LIS_h0,5002,5001,tcp,1.0,,0.11918598712533886,1.4580504894256592
BAR_h0,MAD_h0,5000,5001,tcp,1.0,,0.058674282065072164,1.6607413291931152
BAR_h0,MAN_h0,5001,5001,tcp,1.0,,0.1586788899701006,1.9901399612426758
```


# Output file

The output looks as follows:

```
id,type,target,value,matches,statisfied
prr_0,prr,50.0,1.0,6,True
fct_0,fct,1000.0,1.6607413291931152,1,True
delay_0,delay,50.0,-inf,0,False
rtt_0,rtt,100.0,0.1586788899701006,3,True
wp_0,wp,PAR,,0,False
```

In particular, it specifies how many flows where matched, and whether the
SLA is satisfied overall.


# Adding new SLAs

To add addictional SLAs, simply subclass the SLA baseclass and specify the
`TYPE` as well as the `update` method.
The type determines for which SLA this class will be used, and update is called
for every row in the result file. The update should update (hence the name)
the current SLA value and whether it is satisfied.

```
class MySLA(SLA):
    TYPE = "slatype"

    def update(self, result):
        self.value = "new"
        self.satisfied = True
```

The SLA base class takes care of only considering the relevant flows, you can
assume that update is only called for flows that the SLA applies to.
"""

import csv
import typing
import os


# Main function.
# ==============

def check_slas(sla_file: os.PathLike,
               result_file: os.PathLike,
               output_file: typing.Optional[os.PathLike] = None) \
        -> typing.List[dict]:
    """Load SLAs and check results, writing to output file."""
    with open(sla_file, "r", newline='') as slafile:
        reader = csv.DictReader(cleanfile(slafile))
        slas = [SLA.make(row) for row in reader]

    assert slas, "No SLAs specified!"

    with open(result_file, "r", newline='') as resfile:
        reader = csv.DictReader(cleanfile(resfile))
        for result in reader:
            for sla in slas:
                sla.update_if_match(result)

    results = [sla.result for sla in slas]

    if output_file is not None:
        fieldnames = list(results[0].keys())
        with open(output_file, "w", newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames)
            writer.writeheader()
            writer.writerows(results)

    return results


# SLA classes.
# ============

formattype = typing.TypeVar('formattype')


class SLA:
    """Service level agreement."""
    TYPE = None
    RANGE_SEPARATOR = '--'
    WILDCARD = "*"

    @classmethod
    def make(cls, specification):
        """Find and init a SLA subclass for the specified type (recursively)."""
        if cls.TYPE == specification['type']:
            return cls(specification)
        for subclass in cls.__subclasses__():
            result = subclass.make(specification)
            if result is not None:
                return result
        return None

    def __init__(self, specification):
        # Parse specification.
        if self.TYPE is not None:
            assert specification['type'] == self.TYPE
        self.id = specification['id']
        self.target = specification['target']

        self.protocol = self._format(specification['protocol'], str)
        self.src = self._format(specification['src'], str)
        self.dst = self._format(specification['dst'], str)
        self.sport = self._parse_port(specification['sport'])
        self.dport = self._parse_port(specification['dport'])

        self.matches = 0  # How many flows were matched.
        self.value = ""
        self.satisfied = False

    def _parse_port(self, port: str):
        try:
            start, end = port.split(self.RANGE_SEPARATOR)
        except ValueError:  # Only one value, not a range.
            start = end = port
        return (self._format(start, int), self._format(end, int))

    def _format(self, value: str,
                formatter: typing.Callable[[str], formattype]) \
            -> typing.Optional[formattype]:
        return None if value == self.WILDCARD else formatter(value)

    def update_if_match(self, result: typing.Dict[str, str]):
        """If a ."""
        if self.match(result):
            self.matches += 1
            self.update(result)

    def match(self, result):
        """Return True if flow matches the spec."""
        if self.protocol is not None and (result['protocol'] != self.protocol):
            return False
        for (own, key) in ((self.src, 'src'), (self.dst, 'dst')):
            if (own is not None) and result[key] != own:
                return False
        for ((lo, hi), key) in ((self.sport, 'sport'), (self.dport, 'dport')):
            value = int(result[key])
            if (lo is not None) and (value < lo):
                return False
            if (hi is not None) and (value > hi):
                return False
        return True

    @property
    def result(self) -> dict:
        """Return a formatted result."""
        return {
            "id": self.id,
            "type": self.TYPE,
            "target": self.target,
            "value": self.value,
            "matches": self.matches,
            "statisfied": self.satisfied,
        }

    def update(self, result: typing.Dict[str, str]):
        """Return the SLA value and whether the SLA is satisfied."""
        raise NotImplementedError


class ThresholdSLA(SLA):
    """Require a value below a threshold."""
    FIELD = ""

    def __init__(self, specification):
        super().__init__(specification)
        self.target = float(self.target)
        self.value = -float("inf")  # Overwritten in first update.

    def update(self, result: typing.Dict[str, str]):
        value = float(result[self.FIELD])
        self.value = max(self.value, value)
        self.satisfied = self.value <= self.target


class PacketReceptionRate(ThresholdSLA):
    """Require PRR below target for all flows."""
    TYPE = "prr"
    FIELD = "prr"


class FlowCompletionTime(ThresholdSLA):
    """Require flow completion time lower than target for all flows."""
    TYPE = 'fct'
    FIELD = "fct"


class Delay(ThresholdSLA):
    """Require delay lower than target for all flows."""
    TYPE = "delay"
    FIELD = "delay"


class RoundtripTime(ThresholdSLA):
    """Require rtt lower than target for all flows."""
    TYPE = "rtt"
    FIELD = "rtt"


class Waypoint(SLA):
    TYPE = 'wp'

    def update(self, result: typing.Dict[str, str]):
        raise NotImplementedError("Cannot veriy waypoint yet.")


# Helper functions.
# =================

def cleanfile(csvfile):
    """Remove comments and whitespace."""
    for row in csvfile:
        raw = row.replace(' ', '').split('#')[0].strip()
        if raw:
            yield raw
