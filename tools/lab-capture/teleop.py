import rclpy, sys
from rclpy.node import Node
from geometry_msgs.msg import Twist
name, vx, wz = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
rclpy.init(); n = Node(name); p = n.create_publisher(Twist, 'cmd_vel', 10)
def tick():
    t = Twist(); t.linear.x = vx; t.angular.z = wz; p.publish(t)
n.create_timer(0.1, tick); rclpy.spin(n)
