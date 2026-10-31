"""A real ROS 2 peer for the executor's ROS 2 adapters (sales-readiness T18).

Runs in a ROS 2 container (rclpy, whatever RMW_IMPLEMENTATION says) and
serves what the `nav2` safe_pause adapter talks to:

* `/navigate_to_pose/_action/cancel_goal` (action_msgs/srv/CancelGoal), as
  an action server's cancel service answers it: ERROR_NONE and the goals
  that were cancelling. The goals "held" follow a script so the executor's
  latch can be checked: the first cancel finds 1 goal (the mission), the
  second none, the third 2 (goals sent while paused), then none;
* a `/cmd_vel` (geometry_msgs/msg/Twist) subscriber counting zero twists.

What it saw is written to /out/peer.json after every event, for the
driver (`motion_tests::t18_real_ros2_peer`, ignored by default).
"""

import json
import os
import sys

import rclpy
from action_msgs.msg import GoalInfo
from action_msgs.srv import CancelGoal
from geometry_msgs.msg import Twist
from rclpy.node import Node

SCRIPT = [1, 0, 2]


class Peer(Node):
    def __init__(self):
        super().__init__("robodr_t18_peer")
        self.cancels = 0
        self.zero_twists = 0
        self.other_twists = 0
        self.create_service(
            CancelGoal, "/navigate_to_pose/_action/cancel_goal", self.on_cancel
        )
        self.create_subscription(Twist, "/cmd_vel", self.on_twist, 10)
        self.dump()

    def dump(self):
        state = {
            "rmw": rclpy.utilities.get_rmw_implementation_identifier(),
            "cancels": self.cancels,
            "zero_twists": self.zero_twists,
            "other_twists": self.other_twists,
        }
        tmp = "/out/peer.json.tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, "/out/peer.json")
        print(json.dumps(state), flush=True)

    def on_cancel(self, request, response):
        n = SCRIPT[self.cancels] if self.cancels < len(SCRIPT) else 0
        self.cancels += 1
        response.return_code = CancelGoal.Response.ERROR_NONE
        for i in range(n):
            g = GoalInfo()
            g.goal_id.uuid = [i + 1] * 16
            response.goals_canceling.append(g)
        self.dump()
        return response

    def on_twist(self, msg):
        zero = (
            msg.linear.x == 0.0
            and msg.linear.y == 0.0
            and msg.linear.z == 0.0
            and msg.angular.x == 0.0
            and msg.angular.y == 0.0
            and msg.angular.z == 0.0
        )
        if zero:
            self.zero_twists += 1
        else:
            self.other_twists += 1
        self.dump()


def main():
    rclpy.init(args=sys.argv)
    node = Peer()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
