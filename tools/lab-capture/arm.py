# Arm trajectory traffic for the DATA_FRAG captures: "pub" sends a
# trajectory_msgs/JointTrajectory with many points (several kB, more than
# one RTPS fragment) on /arm_controller/joint_trajectory at 2 Hz; "sub" is
# the robot side that receives it.
import rclpy, sys
from rclpy.node import Node
from trajectory_msgs.msg import JointTrajectory, JointTrajectoryPoint
from builtin_interfaces.msg import Duration
mode, name = sys.argv[1], sys.argv[2]
rclpy.init(); n = Node(name)
TOPIC = 'arm_controller/joint_trajectory'
if mode == 'sub':
    n.create_subscription(JointTrajectory, TOPIC, lambda m: None, 10)
else:
    points, speed = int(sys.argv[3]), float(sys.argv[4])
    p = n.create_publisher(JointTrajectory, TOPIC, 10)
    joints = [f'joint_{i}' for i in range(1, 7)]
    def tick():
        t = JointTrajectory(); t.joint_names = joints
        for k in range(points):
            pt = JointTrajectoryPoint()
            pt.positions = [0.01 * k * speed] * 6
            pt.velocities = [speed] * 6
            pt.time_from_start = Duration(sec=0, nanosec=10_000_000 * (k + 1))
            t.points.append(pt)
        p.publish(t)
    n.create_timer(0.5, tick)
rclpy.spin(n)
