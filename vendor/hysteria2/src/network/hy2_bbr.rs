use std::{any::Any, sync::Arc};

use rand::{Rng, SeedableRng};

use crate::config::BbrProfile;
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use web_time::{Duration, Instant};

const INITIAL_MTU: u64 = 1252;
const INITIAL_CWND_PACKETS: u64 = 32;
const MIN_CWND_PACKETS: u64 = 4;
const MAX_CWND_PACKETS: u64 = 200;
const MIN_BPS: u64 = 64 * 1024 * 8;
const STARTUP_GROWTH_TARGET: f64 = 1.25;
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
const DEFAULT_MIN_RTT: Duration = Duration::from_millis(100);
const DEFAULT_HIGH_GAIN: f64 = 2.885;
const DERIVED_HIGH_CWND_GAIN: f64 = 2.0;
const GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const ACK_HEIGHT_WINDOW: u64 = GAIN_CYCLE.len() as u64 + 2;
const STARTUP_FULL_LOSS_COUNT: u64 = 8;
const STARTUP_LOSS_THRESHOLD: f64 = 0.02;
const PACER_BURST_INTERVAL: Duration = Duration::from_millis(2);
const PACER_MIN_BURST_PACKETS: u64 = 8;
const PACER_MAX_BURST_PACKETS: u64 = 128;

#[derive(Debug, Clone)]
pub struct Hy2BbrConfig {
  profile: BbrProfile,
  initial_window: u64,
}

impl Hy2BbrConfig {
  pub fn new(profile: BbrProfile) -> Self {
    Self {
      profile,
      initial_window: INITIAL_CWND_PACKETS * INITIAL_MTU,
    }
  }
}

impl ControllerFactory for Hy2BbrConfig {
  fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
    Box::new(Hy2BbrController::new(self, now, current_mtu))
  }
}

#[derive(Debug, Clone)]
pub struct Hy2BbrController {
  config: Arc<Hy2BbrConfig>,
  profile: ProfileConfig,
  mode: BbrMode,
  recovery: RecoveryState,
  rng: rand::rngs::StdRng,

  current_mtu: u64,
  initial_window: u64,
  min_window: u64,
  max_window: u64,
  congestion_window: u64,
  recovery_window: u64,

  max_bandwidth: WindowedMax,
  min_rtt: Duration,
  min_rtt_at: Instant,
  probe_rtt_exit_at: Option<Instant>,
  probe_rtt_round_passed: bool,

  pacing_gain: f64,
  cwnd_gain: f64,
  pacing_rate_bps: u64,
  cycle_index: usize,
  cycle_started_at: Instant,

  round_count: u64,
  current_round_end: u64,
  last_sent_packet: u64,
  largest_acked_packet: u64,
  is_at_full_bandwidth: bool,
  rounds_without_bandwidth_gain: u64,
  bandwidth_at_last_round: u64,
  last_sample_app_limited: bool,
  has_non_app_limited_sample: bool,
  exiting_quiescence: bool,

  ack_aggregation: AckAggregation,
  pacer: RatePacer,
  sent: SentSampler,
  acked_this_event: u64,
  lost_this_event: u64,
  loss_events_this_round: u64,
  lost_bytes_this_round: u64,
}

impl Hy2BbrController {
  fn new(config: Arc<Hy2BbrConfig>, now: Instant, current_mtu: u16) -> Self {
    let mtu = current_mtu as u64;
    let profile = ProfileConfig::from(config.profile);
    let initial_window = config.initial_window.max(MIN_CWND_PACKETS * mtu);
    let mut controller = Self {
      config,
      profile,
      mode: BbrMode::Startup,
      recovery: RecoveryState::NotInRecovery,
      rng: rand::rngs::StdRng::from_os_rng(),
      current_mtu: mtu,
      initial_window,
      min_window: MIN_CWND_PACKETS * mtu,
      max_window: MAX_CWND_PACKETS * mtu,
      congestion_window: initial_window,
      recovery_window: initial_window,
      max_bandwidth: WindowedMax::new(ACK_HEIGHT_WINDOW),
      min_rtt: DEFAULT_MIN_RTT,
      min_rtt_at: now,
      probe_rtt_exit_at: None,
      probe_rtt_round_passed: false,
      pacing_gain: profile.high_gain,
      cwnd_gain: profile.high_cwnd_gain,
      pacing_rate_bps: 0,
      cycle_index: 0,
      cycle_started_at: now,
      round_count: 0,
      current_round_end: 0,
      last_sent_packet: 0,
      largest_acked_packet: 0,
      is_at_full_bandwidth: false,
      rounds_without_bandwidth_gain: 0,
      bandwidth_at_last_round: 0,
      last_sample_app_limited: false,
      has_non_app_limited_sample: false,
      exiting_quiescence: false,
      ack_aggregation: AckAggregation::new(ACK_HEIGHT_WINDOW),
      pacer: RatePacer::new(now, mtu),
      sent: SentSampler::default(),
      acked_this_event: 0,
      lost_this_event: 0,
      loss_events_this_round: 0,
      lost_bytes_this_round: 0,
    };
    controller.enter_startup();
    controller
  }

  fn enter_startup(&mut self) {
    self.mode = BbrMode::Startup;
    self.pacing_gain = self.profile.high_gain;
    self.cwnd_gain = self.profile.high_cwnd_gain;
  }

  fn enter_probe_bw(&mut self, now: Instant) {
    self.mode = BbrMode::ProbeBw;
    self.cwnd_gain = self.profile.cwnd_gain;
    let mut index = self.rng.random_range(0..GAIN_CYCLE.len() - 1);
    if index >= 1 {
      index += 1;
    }
    self.cycle_index = index;
    self.cycle_started_at = now;
    self.pacing_gain = GAIN_CYCLE[index];
  }

  fn on_round_start(&mut self) {
    self.round_count = self.round_count.saturating_add(1);
    self.current_round_end = self.last_sent_packet;
    self.loss_events_this_round = 0;
    self.lost_bytes_this_round = 0;
  }

  fn update_recovery(&mut self, is_round_start: bool, has_losses: bool) {
    if !self.is_at_full_bandwidth {
      return;
    }
    if has_losses {
      self.recovery = match self.recovery {
        RecoveryState::NotInRecovery => {
          self.recovery_window = 0;
          self.current_round_end = self.last_sent_packet;
          RecoveryState::Conservation
        }
        state => state,
      };
    }
    if self.recovery == RecoveryState::Conservation && is_round_start {
      self.recovery = RecoveryState::Growth;
    }
    if !has_losses && self.largest_acked_packet > self.current_round_end {
      self.recovery = RecoveryState::NotInRecovery;
    }
  }

  fn update_gain_cycle(&mut self, now: Instant, in_flight: u64, has_losses: bool) {
    let mut advance = now.saturating_duration_since(self.cycle_started_at) > self.min_rtt;
    if self.pacing_gain > 1.0 && !has_losses && in_flight < self.target_window(self.pacing_gain) {
      advance = false;
    }
    if self.pacing_gain < 1.0 && in_flight <= self.target_window(1.0) {
      advance = true;
    }
    if !advance {
      return;
    }
    self.cycle_index = (self.cycle_index + 1) % GAIN_CYCLE.len();
    self.cycle_started_at = now;
    if self.profile.drain_to_target
      && self.pacing_gain < 1.0
      && GAIN_CYCLE[self.cycle_index] == 1.0
      && in_flight > self.target_window(1.0)
    {
      return;
    }
    self.pacing_gain = GAIN_CYCLE[self.cycle_index];
  }

  fn check_full_bandwidth(&mut self) {
    if self.last_sample_app_limited {
      return;
    }
    let bandwidth = self.max_bandwidth.best();
    let target = (self.bandwidth_at_last_round as f64 * STARTUP_GROWTH_TARGET) as u64;
    if bandwidth >= target {
      self.bandwidth_at_last_round = bandwidth;
      self.rounds_without_bandwidth_gain = 0;
      if self.profile.expire_ack_aggregation_startup {
        self.ack_aggregation.reset(self.round_count);
      }
      return;
    }
    self.rounds_without_bandwidth_gain = self.rounds_without_bandwidth_gain.saturating_add(1);
    if self.rounds_without_bandwidth_gain >= self.profile.startup_rounds
      || self.should_exit_startup_due_to_loss()
    {
      self.is_at_full_bandwidth = true;
    }
  }

  fn should_exit_startup_due_to_loss(&self) -> bool {
    self.profile.detect_overshooting
      && self.loss_events_this_round >= STARTUP_FULL_LOSS_COUNT
      && self.lost_bytes_this_round as f64
        > self.congestion_window as f64 * STARTUP_LOSS_THRESHOLD
  }

  fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
    if self.mode == BbrMode::Startup && self.is_at_full_bandwidth {
      self.mode = BbrMode::Drain;
      self.pacing_gain = 1.0 / self.profile.high_gain;
      self.cwnd_gain = self.profile.high_cwnd_gain;
    }
    if self.mode == BbrMode::Drain && in_flight <= self.target_window(1.0) {
      self.enter_probe_bw(now);
    }
  }

  fn maybe_probe_rtt(&mut self, now: Instant, is_round_start: bool, in_flight: u64) {
    let expired = now.saturating_duration_since(self.min_rtt_at) > MIN_RTT_EXPIRY;
    if expired && !self.exiting_quiescence && self.mode != BbrMode::ProbeRtt {
      self.mode = BbrMode::ProbeRtt;
      self.pacing_gain = 1.0;
      self.probe_rtt_exit_at = None;
      self.probe_rtt_round_passed = false;
    }
    if self.mode == BbrMode::ProbeRtt {
      match self.probe_rtt_exit_at {
        None if in_flight < self.probe_rtt_window() + self.current_mtu => {
          self.probe_rtt_exit_at = Some(now + PROBE_RTT_TIME);
        }
        Some(exit_at) => {
          if is_round_start {
            self.probe_rtt_round_passed = true;
          }
          if self.probe_rtt_round_passed && now >= exit_at {
            self.min_rtt_at = now;
            if self.is_at_full_bandwidth {
              self.enter_probe_bw(now);
            } else {
              self.enter_startup();
            }
          }
        }
        _ => {}
      }
    }
    self.exiting_quiescence = false;
  }

  fn update_pacing_rate(&mut self, bytes_lost: u64) {
    let bandwidth = self.max_bandwidth.best();
    if bandwidth == 0 {
      return;
    }
    let target = (bandwidth as f64 * self.pacing_gain) as u64;
    if self.is_at_full_bandwidth {
      self.pacing_rate_bps = target.max(MIN_BPS);
      return;
    }
    if self.pacing_rate_bps == 0 {
      self.pacing_rate_bps = bandwidth_from_delta(self.initial_window, self.min_rtt).max(MIN_BPS);
      return;
    }
    if self.profile.detect_overshooting
      && bytes_lost.saturating_mul(self.profile.bytes_lost_multiplier as u64)
        > self.initial_window
    {
      self.pacing_rate_bps = target.max(self.pacing_rate_bps / 2).max(MIN_BPS);
      return;
    }
    self.pacing_rate_bps = self.pacing_rate_bps.max(target).max(MIN_BPS);
  }

  fn update_window(&mut self, bytes_acked: u64, excess_acked: u64) {
    if self.mode == BbrMode::ProbeRtt {
      return;
    }
    let mut target = self.target_window(self.cwnd_gain);
    if self.is_at_full_bandwidth {
      target = target.saturating_add(self.ack_aggregation.max_height());
      self.congestion_window = target.min(self.congestion_window.saturating_add(bytes_acked));
    } else {
      if self.profile.enable_ack_aggregation_startup {
        target = target.saturating_add(excess_acked);
      }
      if self.congestion_window < target || self.sent.total_acked < self.initial_window {
        self.congestion_window = self.congestion_window.saturating_add(bytes_acked);
      }
    }
    self.congestion_window = self
      .congestion_window
      .clamp(self.min_window, self.max_window);
  }

  fn update_recovery_window(&mut self, bytes_acked: u64, bytes_lost: u64, in_flight: u64) {
    if self.recovery == RecoveryState::NotInRecovery {
      return;
    }
    if self.recovery_window == 0 {
      self.recovery_window = self.min_window.max(in_flight.saturating_add(bytes_acked));
      return;
    }
    self.recovery_window = self
      .recovery_window
      .saturating_sub(bytes_lost)
      .max(self.current_mtu);
    if self.recovery == RecoveryState::Growth {
      self.recovery_window = self.recovery_window.saturating_add(bytes_acked);
    }
    self.recovery_window = self
      .recovery_window
      .max(in_flight.saturating_add(bytes_acked))
      .max(self.min_window);
  }

  fn target_window(&self, gain: f64) -> u64 {
    let bandwidth = self.max_bandwidth.best();
    if bandwidth == 0 {
      return self.initial_window.max(self.min_window);
    }
    let bdp = (bandwidth as f64 * self.min_rtt.as_secs_f64()) as u64;
    ((bdp as f64 * gain) as u64).max(self.min_window)
  }

  fn probe_rtt_window(&self) -> u64 {
    self.min_window
  }

  fn effective_pacing_rate_bps(&self) -> u64 {
    if self.pacing_rate_bps > 0 {
      return self.pacing_rate_bps.max(MIN_BPS);
    }
    let initial_rate = bandwidth_from_delta(self.initial_window, self.min_rtt);
    ((initial_rate as f64 * self.profile.high_gain) as u64).max(MIN_BPS)
  }
}

impl Controller for Hy2BbrController {
  fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
    self.last_sent_packet = last_packet_number;
    if bytes > 0 && self.sent.bytes_in_flight == 0 {
      self.exiting_quiescence = true;
    }
    self.sent.on_sent(now, bytes);
  }

  fn on_ack(
    &mut self,
    now: Instant,
    sent: Instant,
    bytes: u64,
    app_limited: bool,
    rtt: &RttEstimator,
  ) {
    self.acked_this_event = self.acked_this_event.saturating_add(bytes);
    self.last_sample_app_limited = app_limited;
    self.has_non_app_limited_sample |= !app_limited;
    self.sent.on_ack(bytes);
    let sample_rtt = now.saturating_duration_since(sent);
    let measured_rtt = rtt.min().min(sample_rtt).max(Duration::from_millis(1));
    if measured_rtt < self.min_rtt || now.saturating_duration_since(self.min_rtt_at) > MIN_RTT_EXPIRY {
      self.min_rtt = measured_rtt;
      self.min_rtt_at = now;
    }
    let bandwidth = bandwidth_from_delta(bytes, sample_rtt);
    if bandwidth > 0 && (!app_limited || bandwidth > self.max_bandwidth.best()) {
      self.max_bandwidth.update(self.round_count, bandwidth);
    }
  }

  fn on_end_acks(
    &mut self,
    now: Instant,
    in_flight: u64,
    app_limited: bool,
    largest_packet_num_acked: Option<u64>,
  ) {
    if let Some(packet) = largest_packet_num_acked {
      self.largest_acked_packet = packet;
    }
    let is_round_start = self.largest_acked_packet > self.current_round_end;
    if is_round_start {
      self.on_round_start();
    }
    let has_losses = self.lost_this_event > 0;
    self.update_recovery(is_round_start, has_losses);
    if self.mode == BbrMode::ProbeBw {
      self.update_gain_cycle(now, in_flight, has_losses);
    }
    if is_round_start && !self.is_at_full_bandwidth {
      self.check_full_bandwidth();
    }
    self.maybe_exit_startup_or_drain(now, in_flight);
    self.maybe_probe_rtt(now, is_round_start, in_flight);
    let excess_acked = self.ack_aggregation.update(
      now,
      self.round_count,
      self.acked_this_event,
      self.max_bandwidth.best(),
      self.last_sent_packet,
      self.largest_acked_packet,
      self.profile.reduce_extra_ack_on_bandwidth_increase && is_round_start,
    );
    self.update_pacing_rate(self.lost_this_event);
    self.update_window(self.acked_this_event, excess_acked);
    self.update_recovery_window(self.acked_this_event, self.lost_this_event, in_flight);
    self.sent.bytes_in_flight = in_flight;
    if app_limited && in_flight < self.target_window(1.0) {
      self.last_sample_app_limited = true;
    }
    self.acked_this_event = 0;
    self.lost_this_event = 0;
  }

  fn on_congestion_event(
    &mut self,
    _now: Instant,
    _sent: Instant,
    _is_persistent_congestion: bool,
    lost_bytes: u64,
  ) {
    self.lost_this_event = self.lost_this_event.saturating_add(lost_bytes);
    self.loss_events_this_round = self.loss_events_this_round.saturating_add(1);
    self.lost_bytes_this_round = self.lost_bytes_this_round.saturating_add(lost_bytes);
    self.sent.on_lost(lost_bytes);
  }

  fn on_mtu_update(&mut self, new_mtu: u16) {
    self.current_mtu = new_mtu as u64;
    self.min_window = MIN_CWND_PACKETS * self.current_mtu;
    self.max_window = MAX_CWND_PACKETS * self.current_mtu;
    self.initial_window = self.config.initial_window.max(self.min_window);
    self.congestion_window = self.congestion_window.clamp(self.min_window, self.max_window);
  }

  fn window(&self) -> u64 {
    if self.mode == BbrMode::ProbeRtt {
      return self.probe_rtt_window();
    }
    if self.recovery != RecoveryState::NotInRecovery {
      return self.congestion_window.min(self.recovery_window);
    }
    self.congestion_window
  }

  fn supports_custom_pacing(&self) -> bool {
    true
  }

  fn pacing_delay(&mut self, now: Instant, bytes_to_send: u64, mtu: u16) -> Option<Instant> {
    self
      .pacer
      .delay(now, self.effective_pacing_rate_bps(), bytes_to_send, mtu as u64)
  }

  fn on_pacing_packet_sent(&mut self, now: Instant, bytes: u64) {
    self
      .pacer
      .on_packet_sent(now, self.effective_pacing_rate_bps(), bytes, self.current_mtu);
  }

  fn metrics(&self) -> ControllerMetrics {
    let mut metrics = ControllerMetrics::default();
    metrics.congestion_window = self.window();
    metrics.pacing_rate = Some(self.effective_pacing_rate_bps());
    metrics
  }

  fn clone_box(&self) -> Box<dyn Controller> {
    Box::new(self.clone())
  }

  fn initial_window(&self) -> u64 {
    self.initial_window
  }

  fn into_any(self: Box<Self>) -> Box<dyn Any> {
    self
  }
}

#[derive(Clone, Debug)]
pub(crate) struct RatePacer {
  tokens: u64,
  capacity: u64,
  last: Instant,
  last_mtu: u64,
}

impl RatePacer {
  pub(crate) fn new(now: Instant, mtu: u64) -> Self {
    let capacity = PACER_MIN_BURST_PACKETS * mtu;
    Self {
      tokens: capacity,
      capacity,
      last: now,
      last_mtu: mtu,
    }
  }

  pub(crate) fn delay(
    &mut self,
    now: Instant,
    pacing_rate_bps: u64,
    bytes_to_send: u64,
    mtu: u64,
  ) -> Option<Instant> {
    let rate = pacing_rate_bps.max(MIN_BPS);
    self.refill(now, rate, mtu);
    if self.tokens >= bytes_to_send {
      return None;
    }
    let deficit = bytes_to_send.saturating_sub(self.tokens);
    let seconds = (deficit as f64 * 8.0) / rate as f64;
    Some(now + Duration::from_secs_f64(seconds.max(0.000_2)))
  }

  pub(crate) fn on_packet_sent(
    &mut self,
    now: Instant,
    pacing_rate_bps: u64,
    bytes: u64,
    mtu: u64,
  ) {
    self.refill(now, pacing_rate_bps.max(MIN_BPS), mtu);
    self.tokens = self.tokens.saturating_sub(bytes);
  }

  fn refill(&mut self, now: Instant, pacing_rate_bps: u64, mtu: u64) {
    let capacity = burst_capacity(pacing_rate_bps, mtu);
    if capacity != self.capacity || mtu != self.last_mtu {
      self.capacity = capacity;
      self.tokens = self.tokens.min(capacity);
      self.last_mtu = mtu;
    }
    let elapsed = now.saturating_duration_since(self.last);
    if !elapsed.is_zero() {
      let add = ((pacing_rate_bps as f64 / 8.0) * elapsed.as_secs_f64()) as u64;
      self.tokens = self.tokens.saturating_add(add).min(self.capacity);
      self.last = now;
    }
  }
}

fn burst_capacity(pacing_rate_bps: u64, mtu: u64) -> u64 {
  let by_time = ((pacing_rate_bps as f64 / 8.0) * PACER_BURST_INTERVAL.as_secs_f64()) as u64;
  by_time.clamp(PACER_MIN_BURST_PACKETS * mtu, PACER_MAX_BURST_PACKETS * mtu)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BbrMode {
  Startup,
  Drain,
  ProbeBw,
  ProbeRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryState {
  NotInRecovery,
  Conservation,
  Growth,
}

#[derive(Clone, Copy, Debug)]
struct ProfileConfig {
  high_gain: f64,
  high_cwnd_gain: f64,
  cwnd_gain: f64,
  startup_rounds: u64,
  drain_to_target: bool,
  detect_overshooting: bool,
  bytes_lost_multiplier: u8,
  enable_ack_aggregation_startup: bool,
  expire_ack_aggregation_startup: bool,
  reduce_extra_ack_on_bandwidth_increase: bool,
}

impl From<BbrProfile> for ProfileConfig {
  fn from(profile: BbrProfile) -> Self {
    match profile {
      BbrProfile::Conservative => Self {
        high_gain: 2.25,
        high_cwnd_gain: 1.75,
        cwnd_gain: 1.75,
        startup_rounds: 2,
        drain_to_target: true,
        detect_overshooting: true,
        bytes_lost_multiplier: 1,
        enable_ack_aggregation_startup: false,
        expire_ack_aggregation_startup: false,
        reduce_extra_ack_on_bandwidth_increase: true,
      },
      BbrProfile::Aggressive => Self {
        high_gain: 3.0,
        high_cwnd_gain: 2.25,
        cwnd_gain: 2.5,
        startup_rounds: 4,
        drain_to_target: false,
        detect_overshooting: false,
        bytes_lost_multiplier: 2,
        enable_ack_aggregation_startup: true,
        expire_ack_aggregation_startup: true,
        reduce_extra_ack_on_bandwidth_increase: false,
      },
      BbrProfile::Standard => Self {
        high_gain: DEFAULT_HIGH_GAIN,
        high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
        cwnd_gain: 2.0,
        startup_rounds: 3,
        drain_to_target: false,
        detect_overshooting: false,
        bytes_lost_multiplier: 2,
        enable_ack_aggregation_startup: false,
        expire_ack_aggregation_startup: false,
        reduce_extra_ack_on_bandwidth_increase: false,
      },
    }
  }
}

#[derive(Clone, Debug, Default)]
struct SentSampler {
  total_sent: u64,
  total_acked: u64,
  total_lost: u64,
  bytes_in_flight: u64,
}

impl SentSampler {
  fn on_sent(&mut self, _now: Instant, bytes: u64) {
    self.total_sent = self.total_sent.saturating_add(bytes);
    self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
  }

  fn on_ack(&mut self, bytes: u64) {
    self.total_acked = self.total_acked.saturating_add(bytes);
    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
  }

  fn on_lost(&mut self, bytes: u64) {
    self.total_lost = self.total_lost.saturating_add(bytes);
    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
  }
}

#[derive(Clone, Debug)]
struct WindowedMax {
  window: u64,
  samples: [(u64, u64); 3],
}

impl WindowedMax {
  fn new(window: u64) -> Self {
    Self {
      window,
      samples: [(0, 0); 3],
    }
  }

  fn best(&self) -> u64 {
    self.samples[0].1
  }

  fn update(&mut self, round: u64, value: u64) {
    if self.samples[0].1 == 0
      || value >= self.samples[0].1
      || round.saturating_sub(self.samples[2].0) > self.window
    {
      self.samples = [(round, value); 3];
      return;
    }
    if value >= self.samples[1].1 {
      self.samples[1] = (round, value);
      self.samples[2] = self.samples[1];
    } else if value >= self.samples[2].1 {
      self.samples[2] = (round, value);
    }
    if round.saturating_sub(self.samples[0].0) > self.window {
      self.samples[0] = self.samples[1];
      self.samples[1] = self.samples[2];
      self.samples[2] = (round, value);
    } else if self.samples[1].0 == self.samples[0].0
      && round.saturating_sub(self.samples[1].0) > self.window / 4
    {
      self.samples[1] = (round, value);
      self.samples[2] = self.samples[1];
    } else if self.samples[2].0 == self.samples[1].0
      && round.saturating_sub(self.samples[2].0) > self.window / 2
    {
      self.samples[2] = (round, value);
    }
  }

  fn reset(&mut self, round: u64) {
    self.samples = [(round, 0); 3];
  }
}

#[derive(Clone, Debug)]
struct AckAggregation {
  max_height: WindowedMax,
  epoch_start: Option<Instant>,
  epoch_bytes: u64,
  last_sent_before_epoch: u64,
}

impl AckAggregation {
  fn new(window: u64) -> Self {
    Self {
      max_height: WindowedMax::new(window),
      epoch_start: None,
      epoch_bytes: 0,
      last_sent_before_epoch: 0,
    }
  }

  fn max_height(&self) -> u64 {
    self.max_height.best()
  }

  fn reset(&mut self, round: u64) {
    self.max_height.reset(round);
  }

  fn update(
    &mut self,
    now: Instant,
    round: u64,
    bytes_acked: u64,
    max_bandwidth: u64,
    last_sent_packet: u64,
    last_acked_packet: u64,
    reduce_on_bandwidth_increase: bool,
  ) -> u64 {
    if max_bandwidth == 0 || bytes_acked == 0 {
      return 0;
    }
    if reduce_on_bandwidth_increase {
      self.max_height.reset(round);
    }
    let force_new_epoch =
      self.last_sent_before_epoch != 0 && last_acked_packet > self.last_sent_before_epoch;
    let Some(start) = self.epoch_start else {
      self.epoch_start = Some(now);
      self.epoch_bytes = bytes_acked;
      self.last_sent_before_epoch = last_sent_packet;
      return 0;
    };
    if force_new_epoch {
      self.epoch_start = Some(now);
      self.epoch_bytes = bytes_acked;
      self.last_sent_before_epoch = last_sent_packet;
      return 0;
    }
    let elapsed = now.saturating_duration_since(start);
    let expected = (max_bandwidth as f64 * elapsed.as_secs_f64()) as u64;
    if self.epoch_bytes <= expected {
      self.epoch_start = Some(now);
      self.epoch_bytes = bytes_acked;
      self.last_sent_before_epoch = last_sent_packet;
      return 0;
    }
    self.epoch_bytes = self.epoch_bytes.saturating_add(bytes_acked);
    let extra = self.epoch_bytes.saturating_sub(expected);
    self.max_height.update(round, extra);
    extra
  }
}

fn bandwidth_from_delta(bytes: u64, delta: Duration) -> u64 {
  if delta.is_zero() {
    return 0;
  }
  ((bytes as f64 * 8.0) / delta.as_secs_f64()) as u64
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn profile_parameters_match_hysteria_shapes() {
    let conservative = ProfileConfig::from(BbrProfile::Conservative);
    let standard = ProfileConfig::from(BbrProfile::Standard);
    let aggressive = ProfileConfig::from(BbrProfile::Aggressive);

    assert!(conservative.high_gain < standard.high_gain);
    assert!(aggressive.high_gain > standard.high_gain);
    assert!(conservative.detect_overshooting);
    assert!(aggressive.enable_ack_aggregation_startup);
  }

  #[test]
  fn ack_aggregation_tracks_extra_acked_bytes() {
    let start = Instant::now();
    let mut agg = AckAggregation::new(10);

    assert_eq!(agg.update(start, 1, 1000, 1000, 10, 0, false), 0);
    let extra = agg.update(
      start + Duration::from_millis(100),
      1,
      5000,
      1000,
      10,
      0,
      false,
    );

    assert!(extra > 0);
    assert_eq!(agg.max_height(), extra);
  }
}
