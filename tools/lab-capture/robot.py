import rclpy, sys
from rclpy.node import Node
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
class Robot(Node):
    def __init__(self):
        super().__init__('base_controller')
        self.sub = self.create_subscription(Twist, 'cmd_vel', self.on_cmd, 10)
        self.pub = self.create_publisher(Odometry, 'odom', 10)
        self.vx = 0.0
        self.create_timer(0.2, self.tick)
    def on_cmd(self, m):
        self.vx = m.linear.x
    def tick(self):
        o = Odometry(); o.header.frame_id = 'odom'; o.child_frame_id = 'base_link'
        o.header.stamp = self.get_clock().now().to_msg(); o.twist.twist.linear.x = self.vx
        self.pub.publish(o)
rclpy.init(); rclpy.spin(Robot())
