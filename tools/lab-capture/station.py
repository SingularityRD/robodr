# Operator station: teleop on /cmd_vel (10 Hz) that also watches /odom, so the
# robot's odometry crosses the wire (a remote reader) as on a real fleet.
import rclpy, sys
from rclpy.node import Node
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
name, vx, wz = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
rclpy.init(); n = Node(name); p = n.create_publisher(Twist, 'cmd_vel', 10)
seen = [0]
def on_odom(m):
    seen[0] += 1
n.create_subscription(Odometry, 'odom', on_odom, 10)
def tick():
    t = Twist(); t.linear.x = vx; t.angular.z = wz; p.publish(t)
n.create_timer(0.1, tick)
try:
    rclpy.spin(n)
finally:
    print(f'{name}: {seen[0]} odom messages', flush=True)
