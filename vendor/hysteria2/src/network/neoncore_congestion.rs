use std::{
  any::Any,
  sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
  },
};

use super::hy2_bbr::{Hy2BbrConfig, Hy2BbrController, RatePacer};
use crate::config::BbrProfile;
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use web_time::Instant;

const INITIAL_MTU: u64 = 1252;
const MIN_ACK_RATE_PERCENT: u64 = 80;
const DEFAULT_RTT_SECS: f64 = 0.333;

#[derive(Debug, Default)]
pub struct NeonCoreHy2CongestionState {
  target_bps: AtomicU64,
  ack_rate_percent: AtomicU64,
}

impl NeonCoreHy2CongestionState {
  pub fn enable_brutal(&self, target_bps: u64) {
    self.target_bps.store(target_bps, Ordering::Relaxed);
    self.ack_rate_percent.store(100, Ordering::Relaxed);
  }

  pub fn use_bbr(&self) {
    self.target_bps.store(0, Ordering::Relaxed);
    self.ack_rate_percent.store(100, Ordering::Relaxed);
  }
}

#[derive(Debug)]
pub struct NeonCoreHy2ControllerFactory {
  state: Arc<NeonCoreHy2CongestionState>,
  bbr: Arc<Hy2BbrConfig>,
  profile: BbrProfile,
}

impl NeonCoreHy2ControllerFactory {
  pub fn new(state: Arc<NeonCoreHy2CongestionState>, profile: BbrProfile) -> Self {
    Self {
      state,
      bbr: Arc::new(Hy2BbrConfig::new(profile)),
      profile,
    }
  }
}

impl ControllerFactory for NeonCoreHy2ControllerFactory {
  fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
    Box::new(NeonCoreHy2Controller {
      state: self.state.clone(),
      bbr: *self
        .bbr
        .clone()
        .build(now, current_mtu)
        .into_any()
        .downcast::<Hy2BbrController>()
        .expect("HY2 BBR factory must build Hy2BbrController"),
      profile: self.profile,
      current_mtu: current_mtu as u64,
      smoothed_rtt_secs: DEFAULT_RTT_SECS,
      pacer: RatePacer::new(now, current_mtu as u64),
      acked_packets: 0,
      lost_packets: 0,
    })
  }
}

struct NeonCoreHy2Controller {
  state: Arc<NeonCoreHy2CongestionState>,
  bbr: Hy2BbrController,
  profile: BbrProfile,
  current_mtu: u64,
  smoothed_rtt_secs: f64,
  pacer: RatePacer,
  acked_packets: u64,
  lost_packets: u64,
}

impl NeonCoreHy2Controller {
  fn brutal_target_bps(&self) -> u64 {
    self.state.target_bps.load(Ordering::Relaxed)
  }

  fn ack_rate(&self) -> f64 {
    let percent = self
      .state
      .ack_rate_percent
      .load(Ordering::Relaxed)
      .max(MIN_ACK_RATE_PERCENT);
    percent as f64 / 100.0
  }

  fn update_ack_rate(&mut self) {
    let total = self.acked_packets + self.lost_packets;
    if total < 50 {
      self.state.ack_rate_percent.store(100, Ordering::Relaxed);
      return;
    }
    let ack_rate = ((self.acked_packets * 100) / total).max(MIN_ACK_RATE_PERCENT);
    self.state.ack_rate_percent.store(ack_rate, Ordering::Relaxed);
    self.acked_packets = 0;
    self.lost_packets = 0;
  }
}

impl Controller for NeonCoreHy2Controller {
  fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
    self.bbr.on_sent(now, bytes, last_packet_number);
  }

  fn on_ack(
    &mut self,
    now: Instant,
    sent: Instant,
    bytes: u64,
    app_limited: bool,
    rtt: &RttEstimator,
  ) {
    self.smoothed_rtt_secs = rtt.get().as_secs_f64().max(0.001);
    self.acked_packets = self.acked_packets.saturating_add(1);
    self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
  }

  fn on_end_acks(
    &mut self,
    now: Instant,
    in_flight: u64,
    app_limited: bool,
    largest_packet_num_acked: Option<u64>,
  ) {
    self.update_ack_rate();
    self
      .bbr
      .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
  }

  fn on_congestion_event(
    &mut self,
    now: Instant,
    sent: Instant,
    is_persistent_congestion: bool,
    lost_bytes: u64,
  ) {
    if lost_bytes > 0 {
      self.lost_packets = self.lost_packets.saturating_add(1);
    }
    self
      .bbr
      .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
  }

  fn on_mtu_update(&mut self, new_mtu: u16) {
    self.current_mtu = new_mtu as u64;
    self.bbr.on_mtu_update(new_mtu);
  }

  fn window(&self) -> u64 {
    let target_bps = self.brutal_target_bps();
    if target_bps == 0 {
      return self.bbr.window();
    }
    let profile = profile_config(self.profile);
    let bdp_window = ((target_bps as f64) * self.smoothed_rtt_secs
      * profile.brutal_window_multiplier
      / self.ack_rate()) as u64;
    bdp_window.max(self.current_mtu)
  }

  fn supports_custom_pacing(&self) -> bool {
    true
  }

  fn pacing_delay(&mut self, now: Instant, bytes_to_send: u64, mtu: u16) -> Option<Instant> {
    let target_bps = self.brutal_target_bps();
    if target_bps == 0 {
      return self.bbr.pacing_delay(now, bytes_to_send, mtu);
    }
    let rate = (target_bps as f64 / self.ack_rate()) as u64;
    self.pacer.delay(now, rate, bytes_to_send, mtu as u64)
  }

  fn on_pacing_packet_sent(&mut self, now: Instant, bytes: u64) {
    let target_bps = self.brutal_target_bps();
    if target_bps == 0 {
      self.bbr.on_pacing_packet_sent(now, bytes);
      return;
    }
    let rate = (target_bps as f64 / self.ack_rate()) as u64;
    self.pacer.on_packet_sent(now, rate, bytes, self.current_mtu);
  }

  fn metrics(&self) -> ControllerMetrics {
    let target_bps = self.brutal_target_bps();
    if target_bps == 0 {
      return self.bbr.metrics();
    }
    let mut metrics = ControllerMetrics::default();
    metrics.congestion_window = self.window();
    metrics.pacing_rate = Some((target_bps as f64 / self.ack_rate()) as u64);
    metrics
  }

  fn clone_box(&self) -> Box<dyn Controller> {
    Box::new(Self {
      state: self.state.clone(),
      bbr: self.bbr.clone(),
      profile: self.profile,
      current_mtu: self.current_mtu,
      smoothed_rtt_secs: self.smoothed_rtt_secs,
      pacer: self.pacer.clone(),
      acked_packets: self.acked_packets,
      lost_packets: self.lost_packets,
    })
  }

  fn initial_window(&self) -> u64 {
    profile_config(self.profile).initial_window
  }

  fn into_any(self: Box<Self>) -> Box<dyn Any> {
    self
  }
}

#[derive(Clone, Copy)]
struct ProfileConfig {
  initial_window: u64,
  brutal_window_multiplier: f64,
}

fn profile_config(profile: BbrProfile) -> ProfileConfig {
  match profile {
    BbrProfile::Conservative => ProfileConfig {
      initial_window: 8 * INITIAL_MTU,
      brutal_window_multiplier: 1.5,
    },
    BbrProfile::Aggressive => ProfileConfig {
      initial_window: 32 * INITIAL_MTU,
      brutal_window_multiplier: 2.5,
    },
    BbrProfile::Standard => ProfileConfig {
      initial_window: 16 * INITIAL_MTU,
      brutal_window_multiplier: 2.0,
    },
  }
}
