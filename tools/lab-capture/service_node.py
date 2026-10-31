# A ROS 2 node that only serves a std_srvs/Trigger service: the extra
# processes on the robot host in the "multi" captures of distributions whose
# base image has no demo_nodes_cpp / action_tutorials_cpp (Humble ros-base).
import rclpy, sys
from rclpy.node import Node
from std_srvs.srv import Trigger
name = sys.argv[1]
rclpy.init(); n = Node(name)
def cb(req, resp):
    resp.success = True
    return resp
n.create_service(Trigger, name + '/trigger', cb)
rclpy.spin(n)
