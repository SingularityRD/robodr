//! DDS type name → decoder registry.
//!
//! ROS 2 RMWs register topic types under the DDS-mangled name
//! `<pkg>::msg::dds_::<Type>_` (that is what SEDP `PID_TYPE_NAME` carries and
//! what `robodr_events::graph::Endpoint::type_name` holds). The registry is
//! keyed by that exact string; [`Registry::with_builtin`] also registers the
//! ROS spelling `<pkg>/msg/<Type>` for configuration convenience. The
//! built-in set includes the Unitree motion types
//! (`unitree_go::msg::dds_::LowCmd_`, `unitree_hg::msg::dds_::LowCmd_`,
//! `unitree_api::msg::dds_::Request_`, ...; see [`crate::unitree`]).

use std::collections::BTreeMap;

use crate::error::DecodeError;
use crate::{decode_payload, Decoded, Limits, MessageKind};

/// A decoder: full serialized payload (encapsulation header included) →
/// decoded message.
pub type DecodeFn = for<'a> fn(&'a [u8], &Limits) -> Result<Decoded<'a>, DecodeError>;

/// Maps DDS type names to decoders.
#[derive(Clone, Default)]
pub struct Registry {
    map: BTreeMap<String, (MessageKind, DecodeFn)>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.map.iter().map(|(k, (kind, _))| (k, kind)))
            .finish()
    }
}

macro_rules! kind_decoder {
    ($name:ident, $kind:expr) => {
        fn $name<'a>(p: &'a [u8], l: &Limits) -> Result<Decoded<'a>, DecodeError> {
            decode_payload($kind, p, l)
        }
    };
}

kind_decoder!(dec_twist, MessageKind::Twist);
kind_decoder!(dec_twist_stamped, MessageKind::TwistStamped);
kind_decoder!(dec_odometry, MessageKind::Odometry);
kind_decoder!(dec_imu, MessageKind::Imu);
kind_decoder!(dec_joint_state, MessageKind::JointState);
kind_decoder!(dec_joint_trajectory, MessageKind::JointTrajectory);
kind_decoder!(dec_unitree_go_low_cmd, MessageKind::UnitreeGoLowCmd);
kind_decoder!(dec_unitree_go_low_state, MessageKind::UnitreeGoLowState);
kind_decoder!(
    dec_unitree_go_sport_state,
    MessageKind::UnitreeGoSportModeState
);
kind_decoder!(dec_unitree_hg_low_cmd, MessageKind::UnitreeHgLowCmd);
kind_decoder!(dec_unitree_hg_low_state, MessageKind::UnitreeHgLowState);
kind_decoder!(dec_unitree_hg_hand_cmd, MessageKind::UnitreeHgHandCmd);
kind_decoder!(dec_unitree_hg_hand_state, MessageKind::UnitreeHgHandState);
kind_decoder!(dec_unitree_hg_imu, MessageKind::UnitreeHgImuState);
kind_decoder!(
    dec_unitree_hg_double_imu,
    MessageKind::UnitreeHgDoubleImuState
);
kind_decoder!(dec_unitree_api_request, MessageKind::UnitreeApiRequest);

/// The built-in decoder for a kind.
pub fn builtin_decoder(kind: MessageKind) -> DecodeFn {
    match kind {
        MessageKind::Twist => dec_twist,
        MessageKind::TwistStamped => dec_twist_stamped,
        MessageKind::Odometry => dec_odometry,
        MessageKind::Imu => dec_imu,
        MessageKind::JointState => dec_joint_state,
        MessageKind::JointTrajectory => dec_joint_trajectory,
        MessageKind::UnitreeGoLowCmd => dec_unitree_go_low_cmd,
        MessageKind::UnitreeGoLowState => dec_unitree_go_low_state,
        MessageKind::UnitreeGoSportModeState => dec_unitree_go_sport_state,
        MessageKind::UnitreeHgLowCmd => dec_unitree_hg_low_cmd,
        MessageKind::UnitreeHgLowState => dec_unitree_hg_low_state,
        MessageKind::UnitreeHgHandCmd => dec_unitree_hg_hand_cmd,
        MessageKind::UnitreeHgHandState => dec_unitree_hg_hand_state,
        MessageKind::UnitreeHgImuState => dec_unitree_hg_imu,
        MessageKind::UnitreeHgDoubleImuState => dec_unitree_hg_double_imu,
        MessageKind::UnitreeApiRequest => dec_unitree_api_request,
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// All built-in kinds, under their DDS and ROS names.
    pub fn with_builtin() -> Self {
        let mut r = Self::new();
        for kind in MessageKind::ALL {
            r.register(kind.dds_type_name(), kind, builtin_decoder(kind));
            r.register(kind.ros_type_name(), kind, builtin_decoder(kind));
        }
        r
    }

    /// Adds or replaces a decoder.
    pub fn register(&mut self, type_name: &str, kind: MessageKind, f: DecodeFn) {
        self.map.insert(type_name.to_owned(), (kind, f));
    }

    /// The kind registered for `type_name` (exact match).
    pub fn kind(&self, type_name: &str) -> Option<MessageKind> {
        self.map.get(type_name).map(|(k, _)| *k)
    }

    /// The decoder registered for `type_name` (exact match).
    pub fn decoder(&self, type_name: &str) -> Option<DecodeFn> {
        self.map.get(type_name).map(|(_, f)| *f)
    }

    /// Decodes `payload` with the decoder for `type_name`.
    pub fn decode<'a>(
        &self,
        type_name: &str,
        payload: &'a [u8],
        limits: &Limits,
    ) -> Result<Decoded<'a>, DecodeError> {
        let f = self.decoder(type_name).ok_or(DecodeError::UnknownType)?;
        f(payload, limits)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Registered type names, sorted.
    pub fn type_names(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(String::as_str)
    }
}
