"""The ROS 2 peer of `peer.py`, on Eclipse Cyclone DDS directly (sales-readiness T18).

Where `rmw_cyclonedds_cpp` cannot be installed (no ROS apt repository), this
peer speaks what it puts on the wire with the Cyclone DDS Python binding
(`cyclonedds` 0.10.x, the Cyclone series ROS 2 Humble ships): the same
topics (`rq/<service>Request`, `rr/<service>Reply`, `rt/cmd_vel`), the same
DDS type names (`action_msgs::srv::dds_::CancelGoal_Request_` ...), the
`rmw_cyclonedds` request header (client GUID as a 64-bit id, sequence
number) leading the request and reply, reliable / volatile QoS. It answers
the same cancel script as `peer.py` and writes /out/peer.json.

It verifies Cyclone DDS's RTPS (discovery, matching on type name,
reliability) against the executor; `rmw_cyclonedds_cpp` itself (its
header layout) is matched by construction, not run. Use `peer.py` with
`Dockerfile.cyclone` for that where the ROS apt repository is reachable.
"""

import json
import os
import time
from dataclasses import dataclass, field

from cyclonedds.core import Listener, Qos, Policy
from cyclonedds.domain import DomainParticipant
from cyclonedds.idl import IdlStruct
from cyclonedds.idl.types import array, int8, int32, int64, sequence, uint8, uint32, uint64
from cyclonedds.pub import DataWriter
from cyclonedds.sub import DataReader
from cyclonedds.topic import Topic
from cyclonedds.util import duration

SCRIPT = [1, 0, 2]


@dataclass
class Time(IdlStruct, typename="builtin_interfaces::msg::dds_::Time_"):
    sec: int32
    nanosec: uint32


@dataclass
class UUID(IdlStruct, typename="unique_identifier_msgs::msg::dds_::UUID_"):
    uuid: array[uint8, 16]


@dataclass
class GoalInfo(IdlStruct, typename="action_msgs::msg::dds_::GoalInfo_"):
    goal_id: UUID
    stamp: Time


@dataclass
class CancelRequest(IdlStruct, typename="action_msgs::srv::dds_::CancelGoal_Request_"):
    client: uint64
    seq: int64
    goal_info: GoalInfo


@dataclass
class CancelResponse(IdlStruct, typename="action_msgs::srv::dds_::CancelGoal_Response_"):
    client: uint64
    seq: int64
    return_code: int8
    goals_canceling: sequence[GoalInfo] = field(default_factory=list)


@dataclass
class Vector3(IdlStruct, typename="geometry_msgs::msg::dds_::Vector3_"):
    x: float
    y: float
    z: float


@dataclass
class Twist(IdlStruct, typename="geometry_msgs::msg::dds_::Twist_"):
    linear: Vector3
    angular: Vector3


state = {"rmw": "cyclonedds (python binding, rmw_cyclonedds wire format)",
         "cancels": 0, "zero_twists": 0, "other_twists": 0}


def dump():
    tmp = "/out/peer.json.tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, "/out/peer.json")
    print(json.dumps(state), flush=True)


def main():
    qos = Qos(
        Policy.Reliability.Reliable(duration(milliseconds=100)),
        Policy.Durability.Volatile,
        Policy.History.KeepLast(10),
    )
    dp = DomainParticipant(0)
    rq = Topic(dp, "rq/navigate_to_pose/_action/cancel_goalRequest", CancelRequest)
    rr = Topic(dp, "rr/navigate_to_pose/_action/cancel_goalReply", CancelResponse)
    tw = Topic(dp, "rt/cmd_vel", Twist)
    replies = DataWriter(dp, rr, qos=qos)

    class OnRequest(Listener):
        def on_data_available(self, reader):
            for req in reader.take(N=16):
                i = state["cancels"]
                n = SCRIPT[i] if i < len(SCRIPT) else 0
                state["cancels"] += 1
                goals = [GoalInfo(UUID([k + 1] * 16), Time(0, 0)) for k in range(n)]
                replies.write(CancelResponse(req.client, req.seq, 0, goals))
                dump()

    class OnTwist(Listener):
        def on_data_available(self, reader):
            for t in reader.take(N=64):
                zero = all(v == 0.0 for v in (t.linear.x, t.linear.y, t.linear.z,
                                              t.angular.x, t.angular.y, t.angular.z))
                state["zero_twists" if zero else "other_twists"] += 1
                dump()

    _requests = DataReader(dp, rq, qos=qos, listener=OnRequest())
    _twists = DataReader(dp, tw, qos=qos, listener=OnTwist())
    dump()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
