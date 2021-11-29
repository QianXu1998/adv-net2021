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
src,dst,sport,dport,protocol,prr,delay,rtt,fct,wpr
BAR_h0,MAN_h0,5001,5001,udp,0.9993718592964824,0.11126276114539932,,,
BAR_h0,LIS_h0,5002,5001,udp,0.9996859296482412,0.13034784026090507,,,
BAR_h0,MAD_h0,5000,5001,udp,1.0,0.005361837320890858,,,
BAR_h0,LIS_h0,5002,5001,tcp,1.0,,0.11918598712533886,1.4580504894256592,
BAR_h0,MAD_h0,5000,5001,tcp,1.0,,0.058674282065072164,1.6607413291931152,
BAR_h0,MAN_h0,5001,5001,tcp,1.0,,0.1586788899701006,1.9901399612426758,
```

If udp flows do not receive at least one packet, delay is empty.
If tcp flows do not complete at all, fct is empty.
If tcp flows do not have at least one packet per direction, rtt is empty.


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
`update` method (the SLA baseclass implements matching already).
The update should update (hence the name) the current SLA value and whether it
is satisfied.
Note that the update method is only called for matching flows.

```
class MySLA(SLA):
    def update(self, result):
        self.value = "new"                       # Update value.
        self.satisfied = (self.value == "new")   # Check if still satisfied.
```

Finally, update the `make_sla` function. This function instantiates the
appropriate SLA for the given SLA type.
"""

import csv
import os
import typing


# Main functions.
# ===============

def check_slas(sla_file: os.PathLike,
               result_file: os.PathLike,
               output_file: typing.Optional[os.PathLike] = None,
               verbose: bool = False) \
        -> typing.List[dict]:
    """Load SLAs and check results, writing to output file.

    If verbose, also print SLA results nicely formatted.
    """
    with open(sla_file, "r", newline='') as slafile:
        reader = csv.DictReader(cleanfile(slafile))
        slas = [make_sla(specification) for specification in reader]

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

    if verbose:
        print()
        h_width = max(len(str(sla_file)), len(str(result_file)))
        print('-' * h_width)
        print('SLA results:')
        print(sla_file)
        print(result_file)
        print('-' * h_width)
        print()

        separator = "-" * 84

        print(separator)
        print("ID       Type  Flows (proto, src, dst, sports, dports)    "
              "#Flows    Tgt    Val   Ok?")
        print(separator)
        len_t = max([len(sla.type) for sla in slas])
        len_i = max([len(sla.id) for sla in slas])

        for sla in slas:
            def _f(val):
                return "*" if val is None else str(val)

            def _v(val):
                if isinstance(val, float):
                    return f"{val:6.2f}"
                return f"{str(val):>6s}"

            flows = (f"{_f(sla.protocol):3s} {_f(sla.src):6s} {_f(sla.dst):6s} "
                     f"{_f(sla.sport[0]):>5s}--{_f(sla.sport[1]):5s} "
                     f"{_f(sla.dport[0]):>5s}--{_f(sla.dport[1]):5s}")

            sla_spec = (f"{sla.id:{len_i}s} {sla.type:{len_t}s} "
                        f"{flows} {str(sla.matches):>5s} "
                        f"{_v(sla.target)} {_v(sla.value)} {sla.satisfied}")
            print(sla_spec)

    return results


def make_sla(specification: dict):
    """Instantiate an SLA object for the provided specification.

    To add new SLA types, add them here!
    """
    sla_type = specification['type']

    if sla_type == "prr":
        return AboveThresholdSLA("prr", specification)
    elif sla_type == "fcr":
        # For TCP flows, we call "prr" "fcr", but it's the same metric.
        return AboveThresholdSLA("prr", specification)
    elif sla_type == "fct":
        return BelowThresholdSLA("fct", specification)
    elif sla_type == "delay":
        return BelowThresholdSLA("delay", specification)
    elif sla_type == "rtt":
        return BelowThresholdSLA("rtt", specification)
    elif sla_type == "wp":
        return WaypointSLA(specification)
    else:
        raise ValueError(f"Type `{sla_type}` does not match any SLA.")


# SLA classes.
# ============
formattype = typing.TypeVar('formattype')


class SLA:
    """Service level agreement.

    The SLA has three main methods:
    - match: Based on specificiton, check if SLA applies to a result.
    - update: Update SLA and check if it is satisfied.
    - update_if_match: First check it match, then update, do nothing otherwise.

    This class already implements matching flows, so subclasses typically
    only need to impement `update`.
    """
    RANGE_SEPARATOR = '--'
    WILDCARD = "*"

    def __init__(self, specification):
        # Parse specification.
        self.id = specification['id']
        self.type = specification['type']
        self.target = specification['target']

        self.protocol = self._format(specification['protocol'], str)
        self.src = self._format(specification['src'], str)
        self.dst = self._format(specification['dst'], str)
        self.sport = self._parse_port(specification['sport'])
        self.dport = self._parse_port(specification['dport'])

        self.matches = 0  # How many flows were matched.
        self.value = None
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
        """If the result matches the specification, call update."""
        if self.match(result):
            self.matches += 1
            self.update(result)

    def match(self, result):
        """Return True if flow matches the spec.

        (Return False if any constraint is violated)
        """
        # Check protocol.
        if self.protocol is not None and (result['protocol'] != self.protocol):
            return False
        # Check source and destination label.
        for (own, key) in ((self.src, 'src'), (self.dst, 'dst')):
            if (own is not None) and result[key] != own:
                return False
        # Check source and destination port ranges.
        for ((lo, hi), key) in ((self.sport, 'sport'), (self.dport, 'dport')):
            value = int(result[key])
            if (lo is not None) and (value < lo):
                return False
            if (hi is not None) and (value > hi):
                return False
        # No constraint was violated; the result matches!
        return True

    @property
    def result(self) -> dict:
        """Return formatted result."""
        return {
            "id": self.id,
            "type": self.type,
            "matches": self.matches,
            "target": self.target,
            "value": "" if self.value is None else self.value,
            "satisfied": self.satisfied,
        }

    def update(self, result: typing.Dict[str, str]):
        """Return the SLA value and whether the SLA is satisfied."""
        raise NotImplementedError  # Implement in sub-classes.


class BelowThresholdSLA(SLA):
    """A generic SLA for a value that is required to be below a threshold.

    Initialize this SLA with the specification and with the result with to
    track, e.g. TresholdSLA('prr', specification) to create an SLA that
    tracks the packet reception rate (prr).

    The specificaiton is parsed to check which flows are matched and to get
    the required target value for the SLA.
    """

    def __init__(self, field: str, specification: dict):
        super().__init__(specification)
        self.field = field
        self.target = float(self.target)

    def update(self, result: typing.Dict[str, str]):
        """Update threshold.

        Get `field` from the current result, remember it if it's above the
        current value (remember largest/worst value).
        The SLA is specified as long as the current value is below target.

        If the value is missing because to many packets were lost, the
        SLA automatically fails (missing value is replaced by infinity).
        """
        str_value = result[self.field]
        value = float(str_value) if str_value else float("inf")
        self.value = value if self.value is None else max(self.value, value)
        self.satisfied = self.value <= self.target


class AboveThresholdSLA(BelowThresholdSLA):
    """Same as BelowThresholdSLA, but requires value above threshold"""

    def update(self, result: typing.Dict[str, str]):
        """Remember minimum value, satisfied if still above threshold.

        See BelowThresholdSLA for details.
        """
        str_value = result[self.field]
        value = float(str_value) if str_value else float("-inf")
        self.value = value if self.value is None else min(self.value, value)
        self.satisfied = self.value >= self.target


class WaypointSLA(SLA):
    """For waypoints, the results contain a waypoint ratio wpr.

    The SLA is satisfied, if the wpr is 1.0 for all flows.
    """

    def update(self, result: typing.Dict[str, str]):
        """Remember min wpr; satisfied if it equals 1.0."""
        value = float(result["wpr"])
        self.value = value if self.value is None else min(self.value, value)
        self.satisfied = self.value == 1.0


# Helper functions.
# =================

def cleanfile(csvfile):
    """Remove comments and whitespace."""
    for row in csvfile:
        raw = row.replace(' ', '').split('#')[0].strip()
        if raw:
            yield raw
