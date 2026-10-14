mod publisher;
mod reset_radar;

use std::convert::Infallible;
use std::io::Cursor;
use std::path::Path;

use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Pixel, Point};
use image::GrayImage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use u8g2_fonts::FontRenderer;
use u8g2_fonts::fonts::{u8g2_font_wqy13_t_gb2312, u8g2_font_wqy15_t_gb2312};
use u8g2_fonts::types::{FontColor, HorizontalAlignment, VerticalPosition};

pub use publisher::{
    FramePublisher, MIN_PUSH_INTERVAL_SECONDS, PublishAttempt, PublishCoordinator, PublisherState,
    ZectrixPublishError, ZectrixPublisher,
};
pub use reset_radar::{
    ParsedRadarStatus, RadarCache, RadarClient, RadarDisplayState, RadarFetch, RadarParseError,
    RadarReason, RadarSemanticState, RadarWatch, ResetConfirmation, ResetKind,
    parse_reset_radar_status,
};

pub const DISPLAY_WIDTH: u32 = 400;
pub const DISPLAY_HEIGHT: u32 = 300;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedQuotaWindow {
    pub name: String,
    pub used_percent: u8,
    pub resets_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedQuota {
    pub windows: Vec<ObservedQuotaWindow>,
    #[serde(default)]
    pub reset_credits: u64,
    #[serde(default)]
    pub stale: bool,
}

#[derive(Clone, Debug, Default)]
pub struct QuotaCache {
    last_known: Option<ObservedQuota>,
}

impl QuotaCache {
    pub fn new(last_known: Option<ObservedQuota>) -> Self {
        Self { last_known }
    }

    pub fn update<E>(
        &mut self,
        observation: Result<ObservedQuota, E>,
    ) -> Result<ObservedQuota, DashboardError> {
        match observation {
            Ok(mut quota) => {
                quota.stale = false;
                self.last_known = Some(quota.clone());
                Ok(quota)
            }
            Err(_) => stale_quota(self.last_known.as_ref()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedDashboardState {
    pub quota: ObservedQuota,
    #[serde(default)]
    pub radar: RadarDisplayState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NormalizedQuotaWindow {
    pub name: String,
    pub used_percent: u8,
    pub remaining_percent: u8,
    pub resets_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NormalizedQuota {
    pub windows: Vec<NormalizedQuotaWindow>,
    pub reset_credits: u64,
    pub stale: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NormalizedDashboardState {
    pub quota: NormalizedQuota,
    pub radar: RadarDisplayState,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DisplayConfig {
    pub previous_frame_hash: Option<String>,
}

pub type DashboardConfig = DisplayConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishDecision {
    Publish,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonochromeFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub sha256: String,
}

impl MonochromeFrame {
    pub fn png_bytes(&self) -> Result<Vec<u8>, DashboardError> {
        let image = GrayImage::from_raw(self.width, self.height, self.pixels.clone())
            .ok_or(DashboardError::InvalidFrame)?;
        let mut output = Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(image)
            .write_to(&mut output, image::ImageFormat::Png)
            .map_err(DashboardError::Image)?;
        Ok(output.into_inner())
    }

    pub fn write_png(&self, path: impl AsRef<Path>) -> Result<(), DashboardError> {
        std::fs::write(path, self.png_bytes()?)
            .map_err(image::ImageError::IoError)
            .map_err(DashboardError::Image)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardOutput {
    pub normalized: NormalizedDashboardState,
    pub frame: MonochromeFrame,
    pub visible_text: Vec<String>,
    pub publish_decision: PublishDecision,
}

#[derive(Debug, Error)]
pub enum DashboardError {
    #[error("failed to render dashboard text: {0}")]
    Font(String),
    #[error("invalid frame dimensions")]
    InvalidFrame,
    #[error("failed to write preview image: {0}")]
    Image(#[source] image::ImageError),
    #[error("额度响应无效：{0}")]
    InvalidQuota(String),
    #[error("没有可用的上次额度数据")]
    MissingQuota,
}

pub fn stale_quota(last_known: Option<&ObservedQuota>) -> Result<ObservedQuota, DashboardError> {
    let mut quota = last_known.cloned().ok_or(DashboardError::MissingQuota)?;
    quota.stale = true;
    Ok(quota)
}

pub fn render_dashboard(
    observed: ObservedDashboardState,
    now_epoch_seconds: i64,
    config: DisplayConfig,
) -> Result<DashboardOutput, DashboardError> {
    let normalized = normalize_dashboard(observed, now_epoch_seconds, &config);
    render_normalized_dashboard(normalized, now_epoch_seconds, config)
}

pub fn normalize_dashboard(
    observed: ObservedDashboardState,
    _now_epoch_seconds: i64,
    _config: &DisplayConfig,
) -> NormalizedDashboardState {
    NormalizedDashboardState {
        quota: NormalizedQuota {
            windows: observed
                .quota
                .windows
                .into_iter()
                .map(|window| NormalizedQuotaWindow {
                    name: window.name,
                    used_percent: window.used_percent.min(100),
                    remaining_percent: 100_u8.saturating_sub(window.used_percent),
                    resets_at_epoch_seconds: window.resets_at_epoch_seconds,
                })
                .collect(),
            reset_credits: observed.quota.reset_credits,
            stale: observed.quota.stale,
        },
        radar: observed.radar,
    }
}

pub fn render_normalized_dashboard(
    normalized: NormalizedDashboardState,
    now_epoch_seconds: i64,
    config: DisplayConfig,
) -> Result<DashboardOutput, DashboardError> {
    render_normalized_dashboard_with_sync(normalized, now_epoch_seconds, config, None)
}

pub fn render_normalized_dashboard_with_sync(
    normalized: NormalizedDashboardState,
    now_epoch_seconds: i64,
    config: DisplayConfig,
    last_successful_sync_epoch_seconds: Option<i64>,
) -> Result<DashboardOutput, DashboardError> {
    let (pixels, visible_text) = draw_dashboard(
        &normalized,
        now_epoch_seconds,
        last_successful_sync_epoch_seconds,
    )?;
    let sha256 = format!("{:x}", Sha256::digest(&pixels));
    let publish_decision = if config.previous_frame_hash.as_deref() == Some(&sha256) {
        PublishDecision::Unchanged
    } else {
        PublishDecision::Publish
    };

    Ok(DashboardOutput {
        normalized,
        frame: MonochromeFrame {
            width: DISPLAY_WIDTH,
            height: DISPLAY_HEIGHT,
            pixels,
            sha256,
        },
        visible_text,
        publish_decision,
    })
}

fn draw_dashboard(
    state: &NormalizedDashboardState,
    now_epoch_seconds: i64,
    _last_successful_sync_epoch_seconds: Option<i64>,
) -> Result<(Vec<u8>, Vec<String>), DashboardError> {
    let mut display = FrameDisplay::new();
    let title_font = FontRenderer::new::<u8g2_font_wqy15_t_gb2312>();
    let body_font = FontRenderer::new::<u8g2_font_wqy13_t_gb2312>();

    let mut visible = Vec::new();

    if !(1..=2).contains(&state.quota.windows.len()) {
        return Err(DashboardError::InvalidQuota(
            "额度窗口数量必须为一或二".into(),
        ));
    }

    // ==========================================
    // 1. 顶部工业风硬朗状态栏 Header (X: 8..390, Y: 6..32)
    // ==========================================
    display.fill_rect(8, 6, 382, 26, BinaryColor::On);
    for (cx, cy) in [(8, 6), (389, 6), (8, 31), (389, 31)] {
        display.draw_pixel(cx, cy, BinaryColor::Off);
    }

    // 左侧白底方块品牌铭牌 [ CODEX ]
    display.fill_rect(12, 10, 66, 18, BinaryColor::Off);
    draw_micro_pixel_str("CODEX", 16, 12, 2, 2, BinaryColor::On, 2, &mut display);

    // 主标题 "配额监控"
    draw_text_color(
        &title_font,
        "配额监控",
        86,
        24,
        BinaryColor::Off,
        &mut display,
    )?;
    visible.push("配额监控".into());

    // 若存在储备重置券，在顶栏中部展示方块徽标
    if state.quota.reset_credits > 0 {
        let credits = state.quota.reset_credits;
        visible.push(format!("重置券×{credits}"));
        display.stroke_rect(158, 10, 82, 18, 1, BinaryColor::Off);
        draw_text_color(
            &body_font,
            "重置券×",
            165,
            23,
            BinaryColor::Off,
            &mut display,
        )?;
        let credits_str = credits.to_string();
        draw_block_number_str(
            credits_str.as_str(),
            220,
            13,
            7,
            12,
            2,
            2,
            false,
            BinaryColor::Off,
            &mut display,
        );
    }

    // 右侧运行/过期状态指示器
    if state.quota.stale {
        // 醒目的白底反色告警模块 + 2px 标准像素感叹号方框
        display.fill_rect(276, 9, 110, 20, BinaryColor::Off);
        display.fill_rect(281, 12, 14, 14, BinaryColor::On);
        display.fill_rect(287, 14, 2, 6, BinaryColor::Off);
        display.fill_rect(287, 22, 2, 2, BinaryColor::Off);
        draw_text_color(
            &body_font,
            "额度未更新",
            300,
            23,
            BinaryColor::On,
            &mut display,
        )?;
        visible.push("额度未更新".into());
    } else {
        // 线框同步状态模块 [ ■ 实时同步 ]
        display.stroke_rect(308, 10, 78, 18, 1, BinaryColor::Off);
        display.fill_rect(315, 16, 6, 6, BinaryColor::Off);
        draw_text_color(
            &body_font,
            "实时同步",
            326,
            23,
            BinaryColor::Off,
            &mut display,
        )?;
        visible.push("已更新".into());
    }

    // ==========================================
    // 2. 中部配额卡片区 (Y: 38 .. 180)
    // ==========================================
    match state.quota.windows.as_slice() {
        [window] => {
            draw_single_quota_card(
                window,
                8,
                38,
                382,
                142,
                now_epoch_seconds,
                &title_font,
                &body_font,
                &mut display,
                &mut visible,
            )?;
        }
        [first, second] => {
            draw_dual_quota_card(
                first,
                8,
                38,
                186,
                142,
                now_epoch_seconds,
                &body_font,
                &mut display,
                &mut visible,
            )?;
            draw_dual_quota_card(
                second,
                204,
                38,
                186,
                142,
                now_epoch_seconds,
                &body_font,
                &mut display,
                &mut visible,
            )?;
        }
        _ => unreachable!(),
    }

    // ==========================================
    // 3. 底部重置雷达控制台 (X: 8, Y: 188, W: 382, H: 102)
    // ==========================================
    draw_modern_reset_radar(
        &state.radar,
        8,
        188,
        382,
        102,
        &title_font,
        &body_font,
        &mut display,
        &mut visible,
    )?;

    Ok((display.pixels, visible))
}

/// 绘制双窗口单张工业风墨水屏卡片 (宽 186, 高 142)
#[allow(clippy::too_many_arguments)]
fn draw_dual_quota_card(
    window: &NormalizedQuotaWindow,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    now_epoch_seconds: i64,
    body_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    let w_i32 = w as i32;

    // 1. 2px 倒角硬朗外框 + 2px 立体实体阴影
    display.draw_chamfer_card(x, y, w, h, 2);

    // 2. 顶部结构化标题栏 (高 23px + 2px 底部主分割线)
    display.fill_rect(x + 2, y + 2, w.saturating_sub(4), 23, BinaryColor::Off);
    display.fill_rect(x + 2, y + 25, w.saturating_sub(4), 2, BinaryColor::On);

    // 左上角斜切黑底窗口铭牌
    let tab_w: u32 = 72;
    display.fill_rect(x + 2, y + 2, tab_w, 23, BinaryColor::On);
    for dy in 0..23_i32 {
        let cut_w = (dy / 3) as u32;
        if cut_w > 0 {
            display.fill_rect(
                x + 2 + tab_w as i32,
                y + 2 + dy,
                cut_w,
                1,
                BinaryColor::On,
            );
        }
    }

    visible.push(window.name.clone());
    draw_window_tab_title(
        body_font,
        window.name.as_str(),
        x + 2 + (tab_w as i32) / 2,
        y + 7,
        BinaryColor::Off,
        display,
    )?;

    // 右上角 "剩余额度" 标识
    draw_text_aligned(
        body_font,
        "剩余额度",
        x + w_i32 - 8,
        y + 18,
        HorizontalAlignment::Right,
        BinaryColor::On,
        display,
    )?;

    // 3. 中部核心方块大数字区 + 右侧已用百分比遥测列
    let remaining_str = window.remaining_percent.to_string();
    visible.push(format!("{remaining_str}% 剩余"));
    let mut cur_dx = x + 10;
    for ch in remaining_str.chars() {
        draw_block_digit(ch, cur_dx, y + 32, 22, 36, 6, true, BinaryColor::On, display);
        cur_dx += 26;
    }
    draw_block_percent(cur_dx + 2, y + 48, 18, 3, BinaryColor::On, display);

    // 右侧已用额度分栏
    draw_dotted_vline(x + w_i32 - 62, y + 31, y + 69, 2, display);
    draw_text_aligned(
        body_font,
        "已用",
        x + w_i32 - 34,
        y + 43,
        HorizontalAlignment::Center,
        BinaryColor::On,
        display,
    )?;
    let used_str = format!("{}%", window.used_percent);
    let used_w = block_number_str_width(used_str.as_str(), 7, 13, 2, 2);
    draw_block_number_str(
        used_str.as_str(),
        x + w_i32 - 34 - (used_w / 2),
        y + 51,
        7,
        13,
        2,
        2,
        false,
        BinaryColor::On,
        display,
    );

    // 4. 10 格工业方块矩阵进度条 (带墨水屏网点底纹与刻度)
    draw_segmented_gauge(
        window.remaining_percent,
        x + 10,
        y + 75,
        w.saturating_sub(20),
        12,
        10,
        display,
    );

    // 5. 底部精确重置时刻区 (Y: y + 96 .. y + 140)
    display.fill_rect(x + 2, y + 96, w.saturating_sub(4), 1, BinaryColor::On);
    display.fill_rect(x + 8, y + 101, 34, 16, BinaryColor::On);
    draw_text_aligned(
        body_font,
        "重置",
        x + 25,
        y + 114,
        HorizontalAlignment::Center,
        BinaryColor::Off,
        display,
    )?;

    let is_long = is_long_quota_window(
        window.name.as_str(),
        window.resets_at_epoch_seconds,
        now_epoch_seconds,
    );
    let reset_label = quota_window_reset_label(
        window.name.as_str(),
        window.resets_at_epoch_seconds,
        now_epoch_seconds,
    );
    visible.push(reset_label);

    if is_long {
        draw_text(body_font, "周期重置时刻", x + 46, y + 114, display)?;
        draw_exact_reset_timestamp(
            body_font,
            true,
            window.resets_at_epoch_seconds,
            x + 10,
            y + 121,
            false,
            display,
        )?;
    } else {
        draw_text(body_font, "窗口重置时刻", x + 46, y + 114, display)?;
        draw_square_clock_icon(x + 10, y + 122, BinaryColor::On, display);
        draw_exact_reset_timestamp(
            body_font,
            false,
            window.resets_at_epoch_seconds,
            x + 28,
            y + 121,
            false,
            display,
        )?;
    }

    Ok(())
}

/// 绘制单窗口居中大卡片 (宽 382, 高 142)
#[allow(clippy::too_many_arguments)]
fn draw_single_quota_card(
    window: &NormalizedQuotaWindow,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    now_epoch_seconds: i64,
    title_font: &FontRenderer,
    body_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    let w_i32 = w as i32;
    let h_i32 = h as i32;

    // 1. 2px 倒角外框与立体阴影
    display.draw_chamfer_card(x, y, w, h, 2);

    // 2. 顶部结构化标题栏
    display.fill_rect(x + 2, y + 2, w.saturating_sub(4), 24, BinaryColor::Off);
    display.fill_rect(x + 2, y + 26, w.saturating_sub(4), 2, BinaryColor::On);

    let tab_w: u32 = 88;
    display.fill_rect(x + 2, y + 2, tab_w, 24, BinaryColor::On);
    for dy in 0..24_i32 {
        let cut_w = (dy / 3) as u32;
        if cut_w > 0 {
            display.fill_rect(
                x + 2 + tab_w as i32,
                y + 2 + dy,
                cut_w,
                1,
                BinaryColor::On,
            );
        }
    }

    visible.push(window.name.clone());
    draw_window_tab_title(
        title_font,
        window.name.as_str(),
        x + 2 + (tab_w as i32) / 2,
        y + 7,
        BinaryColor::Off,
        display,
    )?;

    draw_text_aligned(
        body_font,
        "配额实时状态看板",
        x + w_i32 - 12,
        y + 19,
        HorizontalAlignment::Right,
        BinaryColor::On,
        display,
    )?;

    // 3. 左侧超大方块 HERO 百分比区
    let remaining_str = window.remaining_percent.to_string();
    visible.push(format!("{remaining_str}% 剩余"));
    let mut cur_dx = x + 16;
    for ch in remaining_str.chars() {
        draw_block_digit(ch, cur_dx, y + 38, 28, 48, 7, true, BinaryColor::On, display);
        cur_dx += 34;
    }
    draw_block_percent(cur_dx + 4, y + 62, 22, 4, BinaryColor::On, display);

    draw_text(body_font, "剩余额度 / 已用", x + 16, y + 107, display)?;
    let used_str = format!("{}%", window.used_percent);
    draw_block_number_str(
        used_str.as_str(),
        x + 118,
        y + 96,
        7,
        13,
        2,
        2,
        false,
        BinaryColor::On,
        display,
    );

    // 垂直点阵分割线
    draw_dotted_vline(x + 176, y + 32, y + h_i32 - 8, 2, display);

    // 4. 右侧详情与精确重置时刻区
    let right_x = x + 190;
    draw_text(body_font, "当前额度余量", right_x, y + 45, display)?;
    draw_segmented_gauge(window.remaining_percent, right_x, y + 52, 178, 14, 10, display);

    display.fill_rect(right_x, y + 78, 178, 1, BinaryColor::On);
    display.fill_rect(right_x, y + 86, 36, 16, BinaryColor::On);
    draw_text_aligned(
        body_font,
        "重置",
        right_x + 18,
        y + 99,
        HorizontalAlignment::Center,
        BinaryColor::Off,
        display,
    )?;
    draw_text(body_font, "精确重置时刻", right_x + 42, y + 99, display)?;

    let is_long = is_long_quota_window(
        window.name.as_str(),
        window.resets_at_epoch_seconds,
        now_epoch_seconds,
    );
    let reset_label = quota_window_reset_label(
        window.name.as_str(),
        window.resets_at_epoch_seconds,
        now_epoch_seconds,
    );
    visible.push(reset_label);

    if is_long {
        draw_exact_reset_timestamp(
            body_font,
            true,
            window.resets_at_epoch_seconds,
            right_x,
            y + 109,
            true,
            display,
        )?;
    } else {
        draw_square_clock_icon(right_x, y + 111, BinaryColor::On, display);
        draw_exact_reset_timestamp(
            body_font,
            false,
            window.resets_at_epoch_seconds,
            right_x + 18,
            y + 109,
            true,
            display,
        )?;
    }

    Ok(())
}

/// 绘制底部现代工业风重置雷达控制台 (宽 382, 高 102)
#[allow(clippy::too_many_arguments)]
fn draw_modern_reset_radar(
    radar: &RadarDisplayState,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    title_font: &FontRenderer,
    body_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    let w_i32 = w as i32;

    // 1. 卡片 2px 倒角外框与立体阴影
    display.draw_chamfer_card(x, y, w, h, 2);

    // 2. 顶部结构化标题栏 (高 24px + 2px 分割线)
    display.fill_rect(x + 2, y + 2, w.saturating_sub(4), 24, BinaryColor::Off);
    display.fill_rect(x + 2, y + 26, w.saturating_sub(4), 2, BinaryColor::On);

    draw_square_radar_icon(x + 10, y + 7, BinaryColor::On, display);
    draw_micro_pixel_str("CODEX", x + 30, y + 8, 2, 2, BinaryColor::On, 2, display);
    draw_text(title_font, "重置雷达", x + 94, y + 20, display)?;
    visible.push("重置雷达".into());

    // 3. 右侧状态徽标
    let (status_text, is_highlight) = match radar {
        RadarDisplayState::Unavailable => ("雷达不可用", false),
        RadarDisplayState::NoActiveWatch => ("暂无预测", false),
        RadarDisplayState::Confirmed { kind, .. } => match kind {
            ResetKind::Regular => ("普通重置已记录", true),
            ResetKind::ResetCredit => ("储备重置已记录", true),
        },
        RadarDisplayState::ActiveWatch { stale: true, .. } => ("缓存预测", false),
        RadarDisplayState::ActiveWatch { stale: false, .. } => ("有预测", true),
    };
    visible.push(status_text.into());

    let status_chars = status_text.chars().count() as u32;
    let badge_w = if is_highlight && matches!(radar, RadarDisplayState::ActiveWatch { .. }) {
        status_chars * 13 + 28
    } else {
        status_chars * 13 + 16
    }
    .clamp(68, 160);

    let badge_x = x + w_i32 - (badge_w as i32) - 8;
    if is_highlight {
        display.fill_rect(badge_x, y + 5, badge_w, 18, BinaryColor::On);
        if matches!(radar, RadarDisplayState::ActiveWatch { .. }) {
            display.fill_rect(badge_x + 6, y + 11, 6, 6, BinaryColor::Off);
            draw_text_color(
                body_font,
                status_text,
                badge_x + 18,
                y + 19,
                BinaryColor::Off,
                display,
            )?;
        } else {
            draw_text_aligned(
                body_font,
                status_text,
                badge_x + (badge_w as i32) / 2,
                y + 19,
                HorizontalAlignment::Center,
                BinaryColor::Off,
                display,
            )?;
        }
    } else {
        display.stroke_rect(badge_x, y + 5, badge_w, 18, 1, BinaryColor::On);
        draw_text_aligned(
            body_font,
            status_text,
            badge_x + (badge_w as i32) / 2,
            y + 19,
            HorizontalAlignment::Center,
            BinaryColor::On,
            display,
        )?;
    }

    // 4. 详细内容分派
    match radar {
        RadarDisplayState::ActiveWatch {
            forecast_window,
            reset_chance_percent,
            stale: _,
        } => {
            visible.push(forecast_window.clone());
            let window_text = format!("预测窗口：{forecast_window}");
            let fitted_window = fit_text(body_font, window_text.as_str(), 210);
            draw_mixed_square_cjk(
                body_font,
                fitted_window.as_str(),
                x + 12,
                y + 35,
                BinaryColor::On,
                display,
            )?;

            if let Some(probability) = reset_chance_percent {
                visible.push(format!("重置概率 {probability}%"));
                let num_str = format!("{probability}%");
                let num_w = block_number_str_width(num_str.as_str(), 9, 15, 2, 2);
                let num_x = x + w_i32 - 12 - num_w;
                draw_block_number_str(
                    num_str.as_str(),
                    num_x,
                    y + 33,
                    9,
                    15,
                    2,
                    2,
                    false,
                    BinaryColor::On,
                    display,
                );
                draw_text_aligned(
                    body_font,
                    "重置概率",
                    num_x - 8,
                    y + 46,
                    HorizontalAlignment::Right,
                    BinaryColor::On,
                    display,
                )?;

                // 20 格高精度方块矩阵概率进度条
                let gauge_start_x = x + 12;
                let gauge_y = y + 56;
                let gauge_total_w = w.saturating_sub(24);
                let gauge_h = 14;

                draw_segmented_gauge(
                    *probability,
                    gauge_start_x,
                    gauge_y,
                    gauge_total_w,
                    gauge_h,
                    20,
                    display,
                );

                // 底部 0% - 50% - 100% 像素方块刻度标尺
                draw_micro_pixel_str(
                    "0%",
                    gauge_start_x,
                    y + 78,
                    1,
                    1,
                    BinaryColor::On,
                    1,
                    display,
                );
                draw_micro_pixel_str(
                    "50%",
                    gauge_start_x + (gauge_total_w as i32) / 2 - 9,
                    y + 78,
                    1,
                    1,
                    BinaryColor::On,
                    1,
                    display,
                );
                draw_micro_pixel_str(
                    "100%",
                    gauge_start_x + (gauge_total_w as i32) - 23,
                    y + 78,
                    1,
                    1,
                    BinaryColor::On,
                    1,
                    display,
                );
            } else {
                draw_text_aligned(
                    body_font,
                    "概率未提供",
                    x + w_i32 - 12,
                    y + 46,
                    HorizontalAlignment::Right,
                    BinaryColor::On,
                    display,
                )?;
                visible.push("概率未提供".into());
                draw_segmented_gauge(0, x + 12, y + 56, w.saturating_sub(24), 14, 20, display);
            }
        }
        RadarDisplayState::Confirmed { .. } => {
            display.stroke_rect(x + 12, y + 36, w.saturating_sub(24), 54, 1, BinaryColor::On);
            display.fill_sparse_dots(x + 14, y + 38, 36, 50);
            draw_square_check_icon(x + 24, y + 55, BinaryColor::On, display);
            draw_text(title_font, "公开重置已记录", x + 60, y + 56, display)?;
            draw_text(body_font, "个人额度以实际查询为准", x + 60, y + 77, display)?;
        }
        RadarDisplayState::NoActiveWatch => {
            display.stroke_rect(x + 12, y + 36, w.saturating_sub(24), 54, 1, BinaryColor::On);
            display.fill_sparse_dots(x + 14, y + 38, 36, 50);
            display.fill_rect(x + 23, y + 54, 17, 17, BinaryColor::Off);
            draw_square_clock_icon(x + 25, y + 56, BinaryColor::On, display);
            draw_text(body_font, "当前无公共重置预警信号", x + 60, y + 55, display)?;
            draw_text(body_font, "额度按上方窗口时间重置", x + 60, y + 77, display)?;
        }
        RadarDisplayState::Unavailable => {
            display.stroke_rect(x + 12, y + 36, w.saturating_sub(24), 54, 1, BinaryColor::On);
            display.fill_sparse_dots(x + 14, y + 38, 36, 50);
            display.fill_rect(x + 23, y + 54, 17, 17, BinaryColor::Off);
            display.fill_rect(x + 25, y + 56, 13, 13, BinaryColor::On);
            display.fill_rect(x + 30, y + 58, 3, 5, BinaryColor::Off);
            display.fill_rect(x + 30, y + 65, 3, 2, BinaryColor::Off);
            draw_text(body_font, "公共重置雷达暂不可用", x + 60, y + 55, display)?;
            draw_text(body_font, "下次轮询重试", x + 60, y + 77, display)?;
        }
    }

    Ok(())
}

/// 绘制多格工业方块矩阵进度条（支持墨水屏稀疏网点底纹与微刻度标尺）
fn draw_segmented_gauge(
    percent: u8,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    segments: u32,
    display: &mut FrameDisplay,
) {
    display.stroke_rect(x, y, w, h, 1, BinaryColor::On);
    let inner_x = x + 2;
    let inner_y = y + 2;
    let inner_w = w.saturating_sub(4);
    let inner_h = h.saturating_sub(4);
    let seg_count = segments.max(1);
    let gap = 2_u32;
    let total_gaps = gap * seg_count.saturating_sub(1);
    let seg_w = inner_w.saturating_sub(total_gaps) / seg_count;
    let rem_w = inner_w.saturating_sub(seg_w * seg_count + total_gaps);

    let safe_pct = u32::from(percent.min(100));
    let total_fill_px = (inner_w * safe_pct) / 100;

    let mut cur_x = inner_x;
    for i in 0..seg_count {
        let sw = seg_w + u32::from(i < rem_w);
        let seg_start = (cur_x - inner_x) as u32;
        let seg_end = seg_start + sw;
        if total_fill_px >= seg_end {
            display.fill_rect(cur_x, inner_y, sw, inner_h, BinaryColor::On);
        } else if total_fill_px > seg_start {
            let fill_part = total_fill_px - seg_start;
            display.fill_rect(cur_x, inner_y, fill_part, inner_h, BinaryColor::On);
            display.fill_sparse_dots(
                cur_x + fill_part as i32,
                inner_y,
                sw - fill_part,
                inner_h,
            );
        } else {
            display.fill_sparse_dots(cur_x, inner_y, sw, inner_h);
        }
        cur_x += (sw + gap) as i32;
    }

    // 底部 0%, 25%, 50%, 75%, 100% 刻度线
    let tick_y = y + (h as i32) + 1;
    let w_span = w.saturating_sub(1) as i32;
    for (num, den, tall) in [(0, 4, true), (1, 4, false), (2, 4, true), (3, 4, false), (4, 4, true)]
    {
        let tx = x + (w_span * num) / den;
        let th = if tall { 3 } else { 2 };
        display.fill_rect(tx, tick_y, 1, th, BinaryColor::On);
    }
}

/// 7 段几何方块数字段位表 (A, B, C, D, E, F, G)
fn digit_segments(ch: char) -> Option<[bool; 7]> {
    match ch {
        '0' => Some([true, true, true, true, true, true, false]),
        '1' => Some([false, true, true, false, false, false, false]),
        '2' => Some([true, true, false, true, true, false, true]),
        '3' => Some([true, true, true, true, false, false, true]),
        '4' => Some([false, true, true, false, false, true, true]),
        '5' => Some([true, false, true, true, false, true, true]),
        '6' => Some([true, false, true, true, true, true, true]),
        '7' => Some([true, true, true, false, false, false, false]),
        '8' => Some([true, true, true, true, true, true, true]),
        '9' => Some([true, true, true, true, false, true, true]),
        _ => None,
    }
}

/// 绘制硬朗几何方块数字（支持墨水屏半色调立体阴影与 1px 外倒角）
#[allow(clippy::too_many_arguments)]
fn draw_block_digit(
    ch: char,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    t: u32,
    shadow: bool,
    color: BinaryColor,
    display: &mut FrameDisplay,
) {
    let Some([a, b, c, d, e, f, g]) = digit_segments(ch) else {
        return;
    };
    let w_i32 = w as i32;
    let h_i32 = h as i32;
    let t_i32 = t as i32;
    let mid_y = y + (h_i32 - t_i32) / 2;
    let half_h = ((h_i32 - t_i32) / 2) as u32;

    if ch == '1' {
        let bar_x = x + (w_i32 - t_i32) / 2 + i32::from(w >= 12);
        let beak_w = t.saturating_sub(1).max(2);
        let foot_w = (t + 2 * beak_w).min(w);
        let foot_x = (bar_x - beak_w as i32).max(x);
        let rects = [
            (bar_x - beak_w as i32, y + i32::from(h >= 14), beak_w, t),
            (bar_x, y, t, h),
            (foot_x, y + h_i32 - t_i32, foot_w, t),
        ];
        if shadow && color == BinaryColor::On {
            for (rx, ry, rw, rh) in rects {
                display.fill_halftone(rx + 2, ry + 2, rw, rh, 2);
            }
        }
        for (rx, ry, rw, rh) in rects {
            display.fill_rect(rx, ry, rw, rh, color);
        }
        return;
    }

    let mut rects = Vec::with_capacity(7);
    if a {
        rects.push((x, y, w, t));
    }
    if d {
        rects.push((x, y + h_i32 - t_i32, w, t));
    }
    if g {
        rects.push((x, mid_y, w, t));
    }
    if f {
        rects.push((x, y, t, half_h + t));
    }
    if b {
        rects.push((x + w_i32 - t_i32, y, t, half_h + t));
    }
    let lower_h = (h_i32 - (mid_y - y)) as u32;
    if e {
        rects.push((x, mid_y, t, lower_h));
    }
    if c {
        rects.push((x + w_i32 - t_i32, mid_y, t, lower_h));
    }

    if shadow && color == BinaryColor::On {
        for &(rx, ry, rw, rh) in &rects {
            display.fill_halftone(rx + 2, ry + 2, rw, rh, 2);
        }
    }
    for (rx, ry, rw, rh) in rects {
        display.fill_rect(rx, ry, rw, rh, color);
    }

    if w >= 10 {
        let inv = if color == BinaryColor::On {
            BinaryColor::Off
        } else {
            BinaryColor::On
        };
        if a && f {
            display.draw_pixel(x, y, inv);
        }
        if a && b {
            display.draw_pixel(x + w_i32 - 1, y, inv);
        }
        if d && e {
            display.draw_pixel(x, y + h_i32 - 1, inv);
        }
        if d && c {
            display.draw_pixel(x + w_i32 - 1, y + h_i32 - 1, inv);
        }
    }
}

/// 绘制几何方块百分号 `%`
fn draw_block_percent(
    x: i32,
    y: i32,
    size: u32,
    t: u32,
    color: BinaryColor,
    display: &mut FrameDisplay,
) {
    let dot = (size / 3).max(t + 1);
    let size_i32 = size as i32;
    let dot_i32 = dot as i32;
    display.fill_rect(x, y, dot, dot, color);
    display.fill_rect(x + size_i32 - dot_i32, y + size_i32 - dot_i32, dot, dot, color);
    let steps = size.saturating_sub(2) as i32;
    let half_t = (t / 2) as i32;
    for i in 0..steps {
        let px = x + 1 + i;
        let py = y + size_i32 - 2 - i;
        display.fill_rect(px, py - half_t, t, t, color);
    }
}

/// 计算方块数字字符串渲染宽度
fn block_number_str_width(text: &str, dw: u32, dh: u32, dt: u32, gap: i32) -> i32 {
    let mut width = 0_i32;
    for ch in text.chars() {
        let w = if ch.is_ascii_digit() {
            dw as i32
        } else if ch == ':' {
            dt.max(2) as i32 + 2
        } else if ch == '-' {
            dw.saturating_sub(2).max(4) as i32
        } else if ch == '%' {
            dh.saturating_sub(2).max(8) as i32
        } else {
            (dw / 2) as i32
        };
        width += w + gap;
    }
    (width - gap).max(0)
}

/// 绘制方块数字与符号串 (`0-9`, `:`, `-`, `%`)
#[allow(clippy::too_many_arguments)]
fn draw_block_number_str(
    text: &str,
    x: i32,
    y: i32,
    dw: u32,
    dh: u32,
    dt: u32,
    gap: i32,
    shadow: bool,
    color: BinaryColor,
    display: &mut FrameDisplay,
) -> i32 {
    let mut cx = x;
    let dh_i32 = dh as i32;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            draw_block_digit(ch, cx, y, dw, dh, dt, shadow, color, display);
            cx += (dw as i32) + gap;
        } else if ch == ':' {
            let dot = dt.max(2);
            let dot_i32 = dot as i32;
            display.fill_rect(cx + 1, y + dh_i32 / 4, dot, dot, color);
            display.fill_rect(cx + 1, y + (dh_i32 * 3) / 4 - dot_i32, dot, dot, color);
            cx += dot_i32 + 2 + gap;
        } else if ch == '-' {
            let mw = dw.saturating_sub(2).max(4);
            display.fill_rect(cx, y + (dh_i32 - dt as i32) / 2, mw, dt, color);
            cx += (mw as i32) + gap;
        } else if ch == '%' {
            let psize = dh.saturating_sub(2).max(8);
            draw_block_percent(
                cx,
                y + (dh_i32 - psize as i32),
                psize,
                dt.saturating_sub(1).max(2),
                color,
                display,
            );
            cx += (psize as i32) + gap;
        } else {
            cx += (dw as i32) / 2 + gap;
        }
    }
    cx - x
}

/// 5x7 像素点阵字库（用于品牌铭牌 CODEX 与标尺刻度 0% / 50% / 100%）
fn micro_pixel_glyph(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        '0' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        '1' => [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        '2' => [0b01110, 0b10001, 0b00001, 0b00110, 0b01000, 0b10000, 0b11111],
        '5' => [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
        '7' => [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
        '%' => [0b11001, 0b11010, 0b00100, 0b00100, 0b01011, 0b10011, 0b00000],
        'C' => [0b01111, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b01111],
        'O' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        'X' => [0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001],
        _ => [0; 7],
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_micro_pixel_str(
    text: &str,
    x: i32,
    y: i32,
    scale_x: u32,
    scale_y: u32,
    color: BinaryColor,
    gap: i32,
    display: &mut FrameDisplay,
) -> i32 {
    let mut cx = x;
    for ch in text.chars() {
        let rows = micro_pixel_glyph(ch);
        for (ry, row) in rows.iter().enumerate() {
            for rx in 0..5_u32 {
                if ((row >> (4 - rx)) & 1) == 1 {
                    display.fill_rect(
                        cx + (rx * scale_x) as i32,
                        y + (ry as u32 * scale_y) as i32,
                        scale_x,
                        scale_y,
                        color,
                    );
                }
            }
        }
        cx += (5 * scale_x) as i32 + gap;
    }
    cx - x
}

/// 绘制窗口标签（自动将前导数字转为方块字，中文保持点阵）
fn draw_window_tab_title(
    font: &FontRenderer,
    name: &str,
    center_x: i32,
    y_top: i32,
    color: BinaryColor,
    display: &mut FrameDisplay,
) -> Result<(), DashboardError> {
    if let Some((num_s, unit_s)) = name.split_once(' ')
        && !num_s.is_empty()
        && num_s.chars().all(|c| c.is_ascii_digit())
    {
        let num_w = block_number_str_width(num_s, 7, 12, 2, 2);
        let unit_w = font
            .get_rendered_dimensions(unit_s, Point::zero(), VerticalPosition::Baseline)
            .map(|d| d.advance.x)
            .unwrap_or((unit_s.chars().count() as i32) * 13);
        let total_w = num_w + 4 + unit_w;
        let start_x = center_x - total_w / 2;
        draw_block_number_str(num_s, start_x, y_top, 7, 12, 2, 2, false, color, display);
        draw_text_color(font, unit_s, start_x + num_w + 4, y_top + 11, color, display)?;
        return Ok(());
    }
    draw_text_aligned(
        font,
        name,
        center_x,
        y_top + 11,
        HorizontalAlignment::Center,
        color,
        display,
    )
}

/// 混合渲染中英文与方块数字（所有数字自动使用几何方块数字，中文使用点阵字）
fn draw_mixed_square_cjk(
    font: &FontRenderer,
    text: &str,
    x: i32,
    y_top: i32,
    color: BinaryColor,
    display: &mut FrameDisplay,
) -> Result<i32, DashboardError> {
    let mut cx = x;
    let mut idx = 0;
    let bytes = text.as_bytes();
    while idx < bytes.len() {
        if bytes[idx].is_ascii_digit() {
            let start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            let num_slice = &text[start..idx];
            let nw = draw_block_number_str(num_slice, cx, y_top, 7, 13, 2, 2, false, color, display);
            cx += nw + 1;
        } else {
            let start = idx;
            while idx < bytes.len() && !bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            let seg = &text[start..idx];
            let trimmed = seg.trim_matches(' ');
            if seg.starts_with(' ') {
                cx += 2;
            }
            if !trimmed.is_empty() {
                draw_text_color(font, trimmed, cx, y_top + 11, color, display)?;
                let w = font
                    .get_rendered_dimensions(trimmed, Point::zero(), VerticalPosition::Baseline)
                    .map(|d| d.advance.x)
                    .unwrap_or((trimmed.chars().count() as i32) * 13);
                cx += w;
            }
            if seg.ends_with(' ') {
                cx += 2;
            }
        }
    }
    Ok(cx - x)
}

/// 绘制精确重置时间戳（5小时窗口：`HH:MM` + `[准点重置]`；7天窗口：`YYYY年MM月DD日 HH时`）
fn draw_exact_reset_timestamp(
    body_font: &FontRenderer,
    is_long: bool,
    resets_at_epoch_seconds: i64,
    x: i32,
    y_top: i32,
    large_single: bool,
    display: &mut FrameDisplay,
) -> Result<(), DashboardError> {
    let Some(utc_dt) = DateTime::<Utc>::from_timestamp(resets_at_epoch_seconds, 0) else {
        draw_text(body_font, "时间未知", x, y_top + 11, display)?;
        return Ok(());
    };
    let local_dt = utc_dt.with_timezone(&Local);
    let mut cx = x;

    if !is_long {
        let hh_mm = format!("{:02}:{:02}", local_dt.hour(), local_dt.minute());
        let (dw, dh, dt_bar) = if large_single {
            (11, 17, 3)
        } else {
            (10, 15, 2)
        };
        let w_clock = draw_block_number_str(
            hh_mm.as_str(),
            cx,
            y_top,
            dw,
            dh,
            dt_bar,
            3,
            false,
            BinaryColor::On,
            display,
        );
        cx += w_clock + 6;
        let tag_y = y_top + i32::from(large_single);
        display.stroke_rect(cx, tag_y, 58, 15, 1, BinaryColor::On);
        draw_text_aligned(
            body_font,
            "准点重置",
            cx + 29,
            tag_y + 12,
            HorizontalAlignment::Center,
            BinaryColor::On,
            display,
        )?;
    } else {
        let (dw, dh, dt_bar) = if large_single { (8, 15, 2) } else { (7, 13, 2) };
        let parts = [
            (format!("{:04}", local_dt.year()), "年"),
            (format!("{:02}", local_dt.month()), "月"),
            (format!("{:02}", local_dt.day()), "日"),
        ];
        for (num_s, unit_s) in parts {
            let w_n = draw_block_number_str(
                num_s.as_str(),
                cx,
                y_top + 1,
                dw,
                dh,
                dt_bar,
                2,
                false,
                BinaryColor::On,
                display,
            );
            cx += w_n;
            draw_text(body_font, unit_s, cx, y_top + 12, display)?;
            cx += 14;
        }
        cx += 2;
        let hour_s = format!("{:02}", local_dt.hour());
        let w_h = draw_block_number_str(
            hour_s.as_str(),
            cx,
            y_top + 1,
            dw,
            dh,
            dt_bar,
            2,
            false,
            BinaryColor::On,
            display,
        );
        cx += w_h;
        draw_text(body_font, "时", cx, y_top + 12, display)?;
    }
    Ok(())
}

/// 绘制点阵竖线
fn draw_dotted_vline(x: i32, y_start: i32, y_end: i32, step: i32, display: &mut FrameDisplay) {
    for y in y_start..=y_end {
        if y % step == 0 {
            display.draw_pixel(x, y, BinaryColor::On);
        }
    }
}

/// 绘制方块勾选图标 (15x15)
fn draw_square_check_icon(x: i32, y: i32, color: BinaryColor, display: &mut FrameDisplay) {
    let inv = if color == BinaryColor::On {
        BinaryColor::Off
    } else {
        BinaryColor::On
    };
    display.fill_rect(x - 1, y - 1, 17, 17, inv);
    display.fill_rect(x, y, 15, 15, color);
    for (cx, cy) in [(x, y), (x + 14, y), (x, y + 14), (x + 14, y + 14)] {
        display.draw_pixel(cx, cy, inv);
    }
    for (dx, dy) in [
        (3, 7),
        (4, 8),
        (5, 9),
        (6, 10),
        (7, 9),
        (8, 8),
        (9, 7),
        (10, 6),
        (11, 5),
        (12, 4),
    ] {
        display.fill_rect(x + dx, y + dy, 2, 2, inv);
    }
}

/// 绘制像素级硬朗方块时钟图标 (13x13)
fn draw_square_clock_icon(x: i32, y: i32, color: BinaryColor, display: &mut FrameDisplay) {
    let inv = if color == BinaryColor::On {
        BinaryColor::Off
    } else {
        BinaryColor::On
    };
    display.fill_rect(x, y, 13, 13, inv);
    display.stroke_rect(x, y, 13, 13, 2, color);
    for (cx, cy) in [(x, y), (x + 12, y), (x, y + 12), (x + 12, y + 12)] {
        display.draw_pixel(cx, cy, inv);
    }
    display.fill_rect(x + 6, y + 3, 2, 4, color);
    display.fill_rect(x + 6, y + 6, 4, 2, color);
}

/// 绘制高识别度工业 HUD 方块雷达图标 (15x15)
fn draw_square_radar_icon(x: i32, y: i32, color: BinaryColor, display: &mut FrameDisplay) {
    let inv = if color == BinaryColor::On {
        BinaryColor::Off
    } else {
        BinaryColor::On
    };
    display.stroke_rect(x, y, 15, 15, 2, color);
    for (cx, cy) in [(x, y), (x + 14, y), (x, y + 14), (x + 14, y + 14)] {
        display.draw_pixel(cx, cy, inv);
    }
    display.stroke_rect(x + 4, y + 4, 7, 7, 1, color);
    display.fill_rect(x + 6, y + 6, 3, 3, color);
    display.fill_rect(x + 7, y + 2, 1, 2, color);
    display.fill_rect(x + 7, y + 11, 1, 2, color);
    display.fill_rect(x + 2, y + 7, 2, 1, color);
    display.fill_rect(x + 11, y + 7, 2, 1, color);
}

/// 判断是否为多日长周期（如 7 天窗口）
pub(crate) fn is_long_quota_window(
    window_name: &str,
    resets_at_epoch_seconds: i64,
    now_epoch_seconds: i64,
) -> bool {
    let lower = window_name.to_ascii_lowercase();
    if window_name.contains('天')
        || window_name.contains('周')
        || window_name.contains('日')
        || lower.contains("day")
        || lower.contains("week")
        || lower.contains("7d")
    {
        return true;
    }
    if window_name.contains("小时")
        || window_name.contains('分')
        || lower.contains("hour")
        || lower.contains("5h")
    {
        return false;
    }
    resets_at_epoch_seconds.saturating_sub(now_epoch_seconds) > 24 * 60 * 60
}

/// 按窗口类型生成精确本地重置时间标签：
/// - 5小时等短期窗口：`重置 HH:MM`
/// - 7天等长周期窗口：`重置 YYYY年MM月DD日 HH时`
pub(crate) fn quota_window_reset_label(
    window_name: &str,
    resets_at_epoch_seconds: i64,
    now_epoch_seconds: i64,
) -> String {
    let Some(utc_dt) = DateTime::<Utc>::from_timestamp(resets_at_epoch_seconds, 0) else {
        return "重置 时间未知".into();
    };
    let local_dt = utc_dt.with_timezone(&Local);
    if is_long_quota_window(window_name, resets_at_epoch_seconds, now_epoch_seconds) {
        format!(
            "重置 {:04}年{:02}月{:02}日 {:02}时",
            local_dt.year(),
            local_dt.month(),
            local_dt.day(),
            local_dt.hour()
        )
    } else {
        format!("重置 {:02}:{:02}", local_dt.hour(), local_dt.minute())
    }
}

#[allow(dead_code)]
pub(crate) fn quota_reset_label(resets_at_epoch_seconds: i64, now_epoch_seconds: i64) -> String {
    quota_window_reset_label("", resets_at_epoch_seconds, now_epoch_seconds)
}

fn draw_text<F: u8g2_fonts::Content>(
    font: &FontRenderer,
    content: F,
    x: i32,
    baseline_y: i32,
    display: &mut FrameDisplay,
) -> Result<(), DashboardError> {
    draw_text_color(font, content, x, baseline_y, BinaryColor::On, display)
}

fn fit_text(font: &FontRenderer, content: &str, max_width: i32) -> String {
    let mut fitted = String::new();
    for character in content.chars() {
        let mut candidate = fitted.clone();
        candidate.push(character);
        let dimensions = font
            .get_rendered_dimensions(
                candidate.as_str(),
                Point::zero(),
                VerticalPosition::Baseline,
            )
            .unwrap();
        if dimensions.advance.x > max_width {
            break;
        }
        fitted.push(character);
    }
    fitted
}

fn draw_text_color<F: u8g2_fonts::Content>(
    font: &FontRenderer,
    content: F,
    x: i32,
    baseline_y: i32,
    color: BinaryColor,
    display: &mut FrameDisplay,
) -> Result<(), DashboardError> {
    font.render(
        content,
        Point::new(x, baseline_y),
        VerticalPosition::Baseline,
        FontColor::Transparent(color),
        display,
    )
    .map(|_| ())
    .map_err(|error| DashboardError::Font(format!("{error:?}")))
}

fn draw_text_aligned<F: u8g2_fonts::Content>(
    font: &FontRenderer,
    content: F,
    x: i32,
    baseline_y: i32,
    alignment: HorizontalAlignment,
    color: BinaryColor,
    display: &mut FrameDisplay,
) -> Result<(), DashboardError> {
    font.render_aligned(
        content,
        Point::new(x, baseline_y),
        VerticalPosition::Baseline,
        alignment,
        FontColor::Transparent(color),
        display,
    )
    .map(|_| ())
    .map_err(|error| DashboardError::Font(format!("{error:?}")))
}

struct FrameDisplay {
    pixels: Vec<u8>,
}

impl FrameDisplay {
    fn new() -> Self {
        Self {
            pixels: vec![255; (DISPLAY_WIDTH * DISPLAY_HEIGHT) as usize],
        }
    }

    #[inline]
    fn draw_pixel(&mut self, x: i32, y: i32, color: BinaryColor) {
        if x >= 0 && y >= 0 && (x as u32) < DISPLAY_WIDTH && (y as u32) < DISPLAY_HEIGHT {
            let index = (y as u32 * DISPLAY_WIDTH + x as u32) as usize;
            self.pixels[index] = if color == BinaryColor::On { 0 } else { 255 };
        }
    }

    fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32, color: BinaryColor) {
        for py in y..y.saturating_add(h as i32) {
            for px in x..x.saturating_add(w as i32) {
                self.draw_pixel(px, py, color);
            }
        }
    }

    fn stroke_rect(&mut self, x: i32, y: i32, w: u32, h: u32, thickness: u32, color: BinaryColor) {
        let t = thickness.min(w).min(h);
        let t_i32 = t as i32;
        let w_i32 = w as i32;
        let h_i32 = h as i32;
        self.fill_rect(x, y, w, t, color);
        self.fill_rect(x, y + h_i32 - t_i32, w, t, color);
        self.fill_rect(x, y, t, h, color);
        self.fill_rect(x + w_i32 - t_i32, y, t, h, color);
    }

    fn fill_halftone(&mut self, x: i32, y: i32, w: u32, h: u32, step: i32) {
        let step = step.max(1);
        for py in y..y.saturating_add(h as i32) {
            for px in x..x.saturating_add(w as i32) {
                if (px + py).rem_euclid(step) == 0 {
                    self.draw_pixel(px, py, BinaryColor::On);
                }
            }
        }
    }

    fn fill_sparse_dots(&mut self, x: i32, y: i32, w: u32, h: u32) {
        for py in y..y.saturating_add(h as i32) {
            for px in x..x.saturating_add(w as i32) {
                if px.rem_euclid(2) == 0 && py.rem_euclid(2) == 0 {
                    self.draw_pixel(px, py, BinaryColor::On);
                }
            }
        }
    }

    fn draw_chamfer_card(&mut self, x: i32, y: i32, w: u32, h: u32, shadow: u32) {
        let w_i32 = w as i32;
        let h_i32 = h as i32;
        if shadow > 0 {
            let s_i32 = shadow as i32;
            self.fill_rect(x + s_i32, y + h_i32, w, shadow, BinaryColor::On);
            self.fill_rect(x + w_i32, y + s_i32, shadow, h, BinaryColor::On);
        }
        self.fill_rect(x, y, w, h, BinaryColor::Off);
        self.stroke_rect(x, y, w, h, 2, BinaryColor::On);
        for (cx, cy) in [
            (x, y),
            (x + w_i32 - 1, y),
            (x, y + h_i32 - 1),
            (x + w_i32 - 1, y + h_i32 - 1),
        ] {
            self.draw_pixel(cx, cy, BinaryColor::Off);
        }
    }
}

impl OriginDimensions for FrameDisplay {
    fn size(&self) -> Size {
        Size::new(DISPLAY_WIDTH, DISPLAY_HEIGHT)
    }
}

impl DrawTarget for FrameDisplay {
    type Color = BinaryColor;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(point, color) in pixels {
            self.draw_pixel(point.x, point.y, color);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_render_various_states_without_panics() {
        let now = 1_797_000_000;
        let radar_states = [
            RadarDisplayState::Unavailable,
            RadarDisplayState::NoActiveWatch,
            RadarDisplayState::Confirmed {
                kind: ResetKind::Regular,
                stale: false,
            },
            RadarDisplayState::Confirmed {
                kind: ResetKind::ResetCredit,
                stale: false,
            },
            RadarDisplayState::ActiveWatch {
                forecast_window: "未来 24 小时".into(),
                reset_chance_percent: Some(85),
                stale: false,
            },
            RadarDisplayState::ActiveWatch {
                forecast_window: "未知窗口".into(),
                reset_chance_percent: None,
                stale: true,
            },
        ];

        for radar in radar_states {
            // 单窗口测试
            let single_output = render_dashboard(
                ObservedDashboardState {
                    quota: ObservedQuota {
                        windows: vec![ObservedQuotaWindow {
                            name: "单窗口".into(),
                            used_percent: 25,
                            resets_at_epoch_seconds: now + 3600,
                        }],
                        reset_credits: 0,
                        stale: false,
                    },
                    radar: radar.clone(),
                },
                now,
                DisplayConfig::default(),
            );
            if let Err(e) = &single_output {
                panic!("single_output error: {e:?}");
            }

            // 双窗口测试
            let dual_output = render_dashboard(
                ObservedDashboardState {
                    quota: ObservedQuota {
                        windows: vec![
                            ObservedQuotaWindow {
                                name: "5 小时".into(),
                                used_percent: 40,
                                resets_at_epoch_seconds: now + 7200,
                            },
                            ObservedQuotaWindow {
                                name: "7 天".into(),
                                used_percent: 80,
                                resets_at_epoch_seconds: now + 86400,
                            },
                        ],
                        reset_credits: 2,
                        stale: true,
                    },
                    radar,
                },
                now,
                DisplayConfig::default(),
            );
            assert!(dual_output.is_ok());
        }
    }

    #[test]
    fn formats_5h_and_7d_exact_reset_timestamps() {
        let now = 1_797_000_000;
        let label_5h = quota_window_reset_label("5 小时", now + 3 * 3600 + 15 * 60, now);
        let label_7d = quota_window_reset_label("7 天", now + 4 * 86_400, now);

        assert!(label_5h.starts_with("重置 ") && label_5h.contains(':'));
        assert!(!label_5h.contains('年'));
        assert!(
            label_7d.contains('年')
                && label_7d.contains('月')
                && label_7d.contains('日')
                && label_7d.ends_with('时')
        );
    }
}
