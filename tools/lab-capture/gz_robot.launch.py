# Headless Gazebo (Harmonic) diff-drive robot for the RoboDR lab captures:
# gz sim server (no GUI, no rendering) with the ros_gz_sim_demos "vehicle"
# world, ros_gz_bridge for /clock, /joint_states, /tf, /tf_static, /cmd_vel
# and /odom, and robot_state_publisher fed from the model's SDF.
#
# One change to the upstream world: its DiffDrive plugin (1 Hz) and its
# OdometryPublisher plugin (50 Hz) both publish on /model/vehicle/odometry,
# so the bridge would merge two odometry streams (different child frames,
# identical stamps every second, different velocities under conflicting
# commands) into one ROS writer. RoboDR's motion monitor reports exactly
# that (duplicate stamps, interleaved values). The lab world moves the
# DiffDrive odometry to a topic that is not bridged.
import os
import re
from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import ExecuteProcess
from launch_ros.actions import Node


def lab_world(demos):
    with open(os.path.join(demos, 'worlds', 'vehicle.sdf')) as f:
        world = f.read()
    with open(os.path.join(demos, 'models', 'vehicle', 'model.sdf')) as f:
        model = f.read()
    inner = model.split("<model name='vehicle'>", 1)[1].rsplit('</model>', 1)[0]
    inner = inner.replace('<pose>0 0 0.325 0 0 0</pose>', '', 1)
    inner = inner.replace(
        '<odom_publish_frequency>1</odom_publish_frequency>',
        '<odom_publish_frequency>1</odom_publish_frequency>'
        '<odom_topic>/model/vehicle/wheel_odometry</odom_topic>'
        '<tf_topic>/model/vehicle/wheel_tf</tf_topic>', 1)
    world = re.sub(r'<include merge="true">\s*<uri>package://ros_gz_sim_demos/models/vehicle</uri>\s*</include>',
                   lambda _: inner, world, count=1)
    world = world.replace('<self_collide>true</self_collide>\n      <pose>0 0 0 0 0 0</pose>',
                          '<self_collide>true</self_collide>\n      <pose>0 0 0.325 0 0 0</pose>', 1)
    path = '/tmp/robodr_lab_vehicle.sdf'
    with open(path, 'w') as f:
        f.write(world)
    return path


def generate_launch_description():
    demos = get_package_share_directory('ros_gz_sim_demos')
    world = lab_world(demos)
    with open(os.path.join(demos, 'models', 'vehicle', 'model.sdf')) as f:
        # sdformat_urdf refuses a <pose> on <model>: drop the model's own.
        robot_desc = f.read().replace('<pose>0 0 0.325 0 0 0</pose>', '', 1)
    gz = '/model/vehicle'
    joints = '/world/demo' + gz + '/joint_state'
    return LaunchDescription([
        ExecuteProcess(cmd=['gz', 'sim', '-s', '-r', '-v', '1', world], output='screen'),
        Node(
            package='ros_gz_bridge', executable='parameter_bridge', name='gz_bridge',
            arguments=[
                '/clock@rosgraph_msgs/msg/Clock[gz.msgs.Clock',
                joints + '@sensor_msgs/msg/JointState[gz.msgs.Model',
                gz + '/pose@tf2_msgs/msg/TFMessage[gz.msgs.Pose_V',
                gz + '/pose_static@tf2_msgs/msg/TFMessage[gz.msgs.Pose_V',
                gz + '/cmd_vel@geometry_msgs/msg/Twist]gz.msgs.Twist',
                gz + '/odometry@nav_msgs/msg/Odometry[gz.msgs.Odometry',
            ],
            remappings=[
                (joints, '/joint_states'),
                (gz + '/pose', '/tf'),
                (gz + '/pose_static', '/tf_static'),
                (gz + '/cmd_vel', '/cmd_vel'),
                (gz + '/odometry', '/odom'),
            ],
            parameters=[{'qos_overrides./tf_static.publisher.durability': 'transient_local'}],
            output='screen'),
        Node(
            package='robot_state_publisher', executable='robot_state_publisher',
            name='robot_state_publisher', output='screen',
            parameters=[{'use_sim_time': True}, {'robot_description': robot_desc}]),
    ])
