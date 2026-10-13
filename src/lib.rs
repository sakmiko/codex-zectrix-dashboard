mod publisher;
mod reset_radar;

use std::convert::Infallible;
use std::io::Cursor;
use std::path::Path;

use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::{DrawTarget, Pixel, Point};
use embedded_graphics::primitives::{
    Circle, CornerRadii, Line, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, RoundedRectangle,
    StyledDrawable,
};
use image::GrayImage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use u8g2_fonts::FontRenderer;
use u8g2_fonts::fonts::{
    u8g2_font_fub14_tr, u8g2_font_fub30_tn, u8g2_font_fub42_tn, u8g2_font_helvB08_tr,
    u8g2_font_helvB10_tr, u8g2_font_helvB12_tr, u8g2_font_wqy13_t_gb2312, u8g2_font_wqy15_t_gb2312,
};
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
    let en_badge_font = FontRenderer::new::<u8g2_font_helvB10_tr>();
    let en_bold_font = FontRenderer::new::<u8g2_font_helvB12_tr>();
    let en_micro_font = FontRenderer::new::<u8g2_font_helvB08_tr>();
    let hero_num_font = FontRenderer::new::<u8g2_font_fub42_tn>();
    let card_num_font = FontRenderer::new::<u8g2_font_fub30_tn>();
    let percent_font = FontRenderer::new::<u8g2_font_fub14_tr>();

    let mut visible = Vec::new();

    if !(1..=2).contains(&state.quota.windows.len()) {
        return Err(DashboardError::InvalidQuota(
            "额度窗口数量必须为一或二".into(),
        ));
    }

    // ==========================================
    // 1. 顶部状态栏 Header (Y: 6 .. 34)
    // ==========================================
    // 黑色品牌微胶囊 [ CODEX ]
    draw_rounded_box(10, 8, 58, 20, 3, None, Some(BinaryColor::On), &mut display);
    draw_text_aligned(
        &en_badge_font,
        "CODEX",
        39,
        22,
        HorizontalAlignment::Center,
        BinaryColor::Off,
        &mut display,
    )?;

    // 主标题 "配额监控"
    draw_text(&title_font, "配额监控", 76, 24, &mut display)?;
    visible.push("配额监控".into());

    // 右侧运行/过期状态
    if state.quota.stale {
        // 醒目的反色告警胶囊
        draw_rounded_box(
            264,
            8,
            126,
            20,
            3,
            None,
            Some(BinaryColor::On),
            &mut display,
        );
        // 小惊叹号圆点
        Circle::new(Point::new(273, 14), 7)
            .draw_styled(&PrimitiveStyle::with_fill(BinaryColor::Off), &mut display)
            .unwrap();
        display.draw_pixel(276, 17, BinaryColor::On);
        draw_text_aligned(
            &body_font,
            "额度未更新",
            335,
            23,
            HorizontalAlignment::Center,
            BinaryColor::Off,
            &mut display,
        )?;
        visible.push("额度未更新".into());
    } else {
        // 优雅的白底线框状态胶囊 [ ● 已更新 ]
        draw_rounded_box(306, 8, 84, 20, 4, Some(BinaryColor::On), None, &mut display);
        Circle::new(Point::new(315, 15), 5)
            .draw_styled(&PrimitiveStyle::with_fill(BinaryColor::On), &mut display)
            .unwrap();
        draw_text(&body_font, "已更新", 325, 23, &mut display)?;
        visible.push("已更新".into());
    }

    // 顶部点阵分割线 (更通透的 33% 墨水屏浅色点阵线)
    draw_dotted_hline(10, 390, 35, 3, &mut display);

    // ==========================================
    // 2. 中部配额卡片区 (Y: 42 .. 182)
    // ==========================================
    match state.quota.windows.as_slice() {
        [window] => {
            // 单窗口：居中大卡片
            draw_single_quota_card(
                window,
                10,
                42,
                380,
                140,
                now_epoch_seconds,
                &title_font,
                &body_font,
                &hero_num_font,
                &percent_font,
                &mut display,
                &mut visible,
            )?;
        }
        [first, second] => {
            // 双窗口：左右两张纯白底色精致工业风卡片
            draw_dual_quota_card(
                first,
                10,
                42,
                186,
                140,
                now_epoch_seconds,
                &body_font,
                &card_num_font,
                &percent_font,
                &mut display,
                &mut visible,
            )?;
            draw_dual_quota_card(
                second,
                204,
                42,
                186,
                140,
                now_epoch_seconds,
                &body_font,
                &card_num_font,
                &percent_font,
                &mut display,
                &mut visible,
            )?;
        }
        _ => unreachable!(),
    }

    // ==========================================
    // 3. 底部重置雷达区 (Y: 190 .. 294)
    // ==========================================
    draw_modern_reset_radar(
        &state.radar,
        10,
        190,
        380,
        102,
        &title_font,
        &body_font,
        &en_bold_font,
        &en_micro_font,
        &mut display,
        &mut visible,
    )?;

    Ok((display.pixels, visible))
}

/// 绘制双窗口单张卡片 (宽 186, 高 140)
#[allow(clippy::too_many_arguments)]
fn draw_dual_quota_card(
    window: &NormalizedQuotaWindow,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    now_epoch_seconds: i64,
    body_font: &FontRenderer,
    number_font: &FontRenderer,
    percent_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    // 1. 卡片圆角外框
    draw_rounded_box(x, y, w, h, 4, Some(BinaryColor::On), None, display);

    // 2. 顶部胶囊标签：窗口名称
    let name_str = window.name.as_str();
    visible.push(window.name.clone());
    let badge_width = (name_str.chars().count() as u32 * 14 + 16).clamp(46, 100);
    draw_rounded_box(
        x + 8,
        y + 8,
        badge_width,
        19,
        3,
        None,
        Some(BinaryColor::On),
        display,
    );
    draw_text_aligned(
        body_font,
        name_str,
        x + 8 + (badge_width as i32) / 2,
        y + 22,
        HorizontalAlignment::Center,
        BinaryColor::Off,
        display,
    )?;

    // 右上角 "剩余额度" 说明 (采用 13 点阵保证笔画绝对清晰)
    draw_text_aligned(
        body_font,
        "剩余额度",
        x + (w as i32) - 8,
        y + 22,
        HorizontalAlignment::Right,
        BinaryColor::On,
        display,
    )?;

    // 3. 核心数值大字
    let remaining_str = window.remaining_percent.to_string();
    visible.push(format!("{remaining_str}% 剩余"));
    draw_text(number_font, remaining_str.as_str(), x + 10, y + 64, display)?;

    // 获取数字渲染宽度以紧贴 "%" 符号
    let num_dims = number_font
        .get_rendered_dimensions(
            remaining_str.as_str(),
            Point::zero(),
            VerticalPosition::Baseline,
        )
        .map(|d| d.advance.x)
        .unwrap_or(36);
    draw_text(percent_font, "%", x + 14 + num_dims, y + 60, display)?;

    // 4. 正式高精度刻度进度条
    let bar_x = x + 10;
    let bar_y = y + 76;
    let bar_w = w.saturating_sub(20);
    let bar_h = 10;
    draw_formal_progress_bar(
        window.remaining_percent,
        bar_x,
        bar_y,
        bar_w,
        bar_h,
        true,
        display,
    );

    // 5. 点阵横向分割线
    draw_dotted_hline(x + 8, x + (w as i32) - 8, y + 99, 3, display);

    // 6. 底部重置倒计时
    let reset_text = quota_reset_label(window.resets_at_epoch_seconds, now_epoch_seconds);
    visible.push(reset_text.clone());
    draw_clock_icon(x + 10, y + 109, display);
    let fitted_reset = fit_text(body_font, reset_text.as_str(), (w as i32) - 34);
    draw_text(body_font, fitted_reset.as_str(), x + 26, y + 121, display)?;

    Ok(())
}

/// 绘制单窗口居中大卡片 (宽 380, 高 140)
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
    hero_num_font: &FontRenderer,
    percent_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    // 1. 卡片圆角外框
    draw_rounded_box(x, y, w, h, 4, Some(BinaryColor::On), None, display);

    // 2. 左侧 HERO 数值区 (宽 180)
    let name_str = window.name.as_str();
    visible.push(window.name.clone());
    let badge_width = (name_str.chars().count() as u32 * 15 + 16).clamp(52, 120);
    draw_rounded_box(
        x + 12,
        y + 10,
        badge_width,
        21,
        3,
        None,
        Some(BinaryColor::On),
        display,
    );
    draw_text_aligned(
        title_font,
        name_str,
        x + 12 + (badge_width as i32) / 2,
        y + 25,
        HorizontalAlignment::Center,
        BinaryColor::Off,
        display,
    )?;

    let remaining_str = window.remaining_percent.to_string();
    visible.push(format!("{remaining_str}% 剩余"));
    draw_text(
        hero_num_font,
        remaining_str.as_str(),
        x + 12,
        y + 84,
        display,
    )?;
    let num_dims = hero_num_font
        .get_rendered_dimensions(
            remaining_str.as_str(),
            Point::zero(),
            VerticalPosition::Baseline,
        )
        .map(|d| d.advance.x)
        .unwrap_or(54);
    draw_text(percent_font, "%", x + 16 + num_dims, y + 78, display)?;
    draw_text(body_font, "剩余额度", x + 14, y + 115, display)?;

    // 垂直点阵分割线
    draw_dotted_vline(x + 175, y + 12, y + (h as i32) - 12, 3, display);

    // 3. 右侧详情区 (X: x + 185)
    let right_x = x + 192;
    draw_text(title_font, "额度状态", right_x, y + 26, display)?;

    let bar_w = 172;
    let bar_h = 12;
    draw_formal_progress_bar(
        window.remaining_percent,
        right_x,
        y + 44,
        bar_w,
        bar_h,
        true,
        display,
    );

    // 进度条刻度说明
    draw_dotted_hline(right_x, right_x + bar_w as i32, y + 76, 3, display);

    // 重置时间信息
    let reset_text = quota_reset_label(window.resets_at_epoch_seconds, now_epoch_seconds);
    visible.push(reset_text.clone());
    draw_clock_icon(right_x + 2, y + 98, display);
    draw_text(
        title_font,
        reset_text.as_str(),
        right_x + 22,
        y + 112,
        display,
    )?;

    Ok(())
}

/// 绘制底部现代重置雷达 (宽 380, 高 102)
#[allow(clippy::too_many_arguments)]
fn draw_modern_reset_radar(
    radar: &RadarDisplayState,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    title_font: &FontRenderer,
    body_font: &FontRenderer,
    en_bold_font: &FontRenderer,
    en_micro_font: &FontRenderer,
    display: &mut FrameDisplay,
    visible: &mut Vec<String>,
) -> Result<(), DashboardError> {
    // 1. 卡片外框
    draw_rounded_box(x, y, w, h, 4, Some(BinaryColor::On), None, display);

    // 2. 标题行与雷达图标
    draw_radar_icon(x + 12, y + 10, display);
    draw_text(title_font, "Codex 重置雷达", x + 34, y + 24, display)?;
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
        status_chars * 13 + 26
    } else {
        status_chars * 13 + 16
    }
    .clamp(60, 160);

    let badge_x = x + (w as i32) - (badge_w as i32) - 8;
    if is_highlight {
        draw_rounded_box(
            badge_x,
            y + 8,
            badge_w,
            20,
            3,
            None,
            Some(BinaryColor::On),
            display,
        );
        if matches!(radar, RadarDisplayState::ActiveWatch { .. }) {
            // 在胶囊左侧画一个精致的实心小白点
            Circle::new(Point::new(badge_x + 8, y + 15), 5)
                .draw_styled(&PrimitiveStyle::with_fill(BinaryColor::Off), display)
                .unwrap();
            draw_text_color(
                body_font,
                status_text,
                badge_x + 18,
                y + 23,
                BinaryColor::Off,
                display,
            )?;
        } else {
            draw_text_aligned(
                body_font,
                status_text,
                badge_x + (badge_w as i32) / 2,
                y + 23,
                HorizontalAlignment::Center,
                BinaryColor::Off,
                display,
            )?;
        }
    } else {
        draw_rounded_box(
            badge_x,
            y + 8,
            badge_w,
            20,
            3,
            Some(BinaryColor::On),
            None,
            display,
        );
        draw_text_aligned(
            body_font,
            status_text,
            badge_x + (badge_w as i32) / 2,
            y + 23,
            HorizontalAlignment::Center,
            BinaryColor::On,
            display,
        )?;
    }

    // 4. 点阵横向分割线
    draw_dotted_hline(x + 8, x + (w as i32) - 8, y + 35, 3, display);

    // 5. 详细内容分派
    match radar {
        RadarDisplayState::ActiveWatch {
            forecast_window,
            reset_chance_percent,
            stale: _,
        } => {
            visible.push(forecast_window.clone());
            let window_text = format!("预测窗口：{forecast_window}");
            draw_text(body_font, window_text.as_str(), x + 12, y + 51, display)?;

            if let Some(probability) = reset_chance_percent {
                visible.push(format!("重置概率 {probability}%"));
                draw_text_aligned(
                    body_font,
                    "重置概率",
                    x + (w as i32) - 52,
                    y + 51,
                    HorizontalAlignment::Right,
                    BinaryColor::On,
                    display,
                )?;
                let num_str = format!("{probability}%");
                draw_text_aligned(
                    en_bold_font,
                    num_str.as_str(),
                    x + (w as i32) - 10,
                    y + 51,
                    HorizontalAlignment::Right,
                    BinaryColor::On,
                    display,
                )?;

                // 正式高精度概率进度条（连续平滑填充）
                let gauge_start_x = x + 12;
                let gauge_y = y + 62;
                let gauge_total_w = w.saturating_sub(24);
                let gauge_h = 11;

                draw_formal_progress_bar(
                    *probability,
                    gauge_start_x,
                    gauge_y,
                    gauge_total_w,
                    gauge_h,
                    true,
                    display,
                );

                // 底部 0% - 50% - 100% 极小刻度标尺
                draw_text(en_micro_font, "0%", gauge_start_x, y + 87, display)?;
                draw_text_aligned(
                    en_micro_font,
                    "50%",
                    gauge_start_x + (gauge_total_w as i32) / 2,
                    y + 87,
                    HorizontalAlignment::Center,
                    BinaryColor::On,
                    display,
                )?;
                draw_text_aligned(
                    en_micro_font,
                    "100%",
                    gauge_start_x + gauge_total_w as i32,
                    y + 87,
                    HorizontalAlignment::Right,
                    BinaryColor::On,
                    display,
                )?;
            } else {
                draw_text(
                    body_font,
                    "概率未提供",
                    x + (w as i32) - 120,
                    y + 51,
                    display,
                )?;
                visible.push("概率未提供".into());
            }
        }
        RadarDisplayState::Confirmed { .. } => {
            draw_rounded_box(
                x + 12,
                y + 44,
                w.saturating_sub(24),
                46,
                3,
                Some(BinaryColor::On),
                None,
                display,
            );
            // 绘制勾选徽标
            draw_check_icon(x + 24, y + 55, display);
            draw_text(title_font, "公开重置已记录", x + 40, y + 64, display)?;
            draw_text(body_font, "个人额度以实际查询为准", x + 24, y + 81, display)?;
        }
        RadarDisplayState::NoActiveWatch => {
            draw_text_aligned(
                body_font,
                "额度按上方窗口时间重置",
                x + (w as i32) / 2,
                y + 68,
                HorizontalAlignment::Center,
                BinaryColor::On,
                display,
            )?;
        }
        RadarDisplayState::Unavailable => {
            draw_text_aligned(
                body_font,
                "下次轮询重试",
                x + (w as i32) / 2,
                y + 68,
                HorizontalAlignment::Center,
                BinaryColor::On,
                display,
            )?;
        }
    }

    Ok(())
}

/// 绘制正式、高精度的工业级进度条（支持内圆角滑块与微刻度标尺）
fn draw_formal_progress_bar(
    percent: u8,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    show_sub_ticks: bool,
    display: &mut FrameDisplay,
) {
    let radius = (h / 2).min(3);
    // 1. 外框轨道（圆角矩形）
    draw_rounded_box(x, y, w, h, radius, Some(BinaryColor::On), None, display);

    // 2. 内部填充滑块（严格按照真实百分比连续精确填充）
    let inner_w = w.saturating_sub(4);
    let inner_h = h.saturating_sub(4);
    let safe_percent = percent.min(100);
    let fill_w = if safe_percent == 0 {
        0
    } else {
        ((inner_w * u32::from(safe_percent)) / 100).max(2)
    };

    if fill_w > 0 && inner_h > 0 {
        let fill_radius = (inner_h / 2).min(2);
        draw_rounded_box(
            x + 2,
            y + 2,
            fill_w,
            inner_h,
            fill_radius,
            None,
            Some(BinaryColor::On),
            display,
        );
    }

    // 3. 正式标尺刻度线 (0%, 50%, 100% 及可选 25%, 75%)
    let tick_y = y + (h as i32) + 2;
    // 0% 刻度
    Line::new(Point::new(x + 2, tick_y), Point::new(x + 2, tick_y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 50% 刻度
    let mid_x = x + (w as i32) / 2;
    Line::new(Point::new(mid_x, tick_y), Point::new(mid_x, tick_y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 100% 刻度
    let end_x = x + (w as i32) - 3;
    Line::new(Point::new(end_x, tick_y), Point::new(end_x, tick_y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();

    if show_sub_ticks {
        // 25% 刻度
        let q1_x = x + (w as i32) / 4;
        display.draw_pixel(q1_x, tick_y, BinaryColor::On);
        // 75% 刻度
        let q3_x = x + ((w as i32) * 3) / 4;
        display.draw_pixel(q3_x, tick_y, BinaryColor::On);
    }
}

/// 绘制圆角矩形
#[allow(clippy::too_many_arguments)]
fn draw_rounded_box(
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    radius: u32,
    stroke_color: Option<BinaryColor>,
    fill_color: Option<BinaryColor>,
    display: &mut FrameDisplay,
) {
    let mut style = PrimitiveStyleBuilder::new();
    if let Some(stroke) = stroke_color {
        style = style.stroke_color(stroke).stroke_width(1);
    }
    if let Some(fill) = fill_color {
        style = style.fill_color(fill);
    }
    RoundedRectangle::new(
        Rectangle::new(Point::new(x, y), Size::new(w, h)),
        CornerRadii::new(Size::new(radius, radius)),
    )
    .draw_styled(&style.build(), display)
    .unwrap();
}

/// 绘制点阵横线（step 控制点阵疏密，如 2 或 3）
fn draw_dotted_hline(x_start: i32, x_end: i32, y: i32, step: i32, display: &mut FrameDisplay) {
    for x in x_start..=x_end {
        if x % step == 0 {
            display.draw_pixel(x, y, BinaryColor::On);
        }
    }
}

/// 绘制点阵竖线
fn draw_dotted_vline(x: i32, y_start: i32, y_end: i32, step: i32, display: &mut FrameDisplay) {
    for y in y_start..=y_end {
        if y % step == 0 {
            display.draw_pixel(x, y, BinaryColor::On);
        }
    }
}

/// 绘制微型勾选图标 (10x10)
fn draw_check_icon(x: i32, y: i32, display: &mut FrameDisplay) {
    Line::new(Point::new(x, y + 5), Point::new(x + 3, y + 8))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 2), display)
        .unwrap();
    Line::new(Point::new(x + 3, y + 8), Point::new(x + 9, y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 2), display)
        .unwrap();
}

/// 绘制像素级精致时钟图标 (11x11)
fn draw_clock_icon(x: i32, y: i32, display: &mut FrameDisplay) {
    Circle::new(Point::new(x, y), 11)
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 中心点与指针
    display.draw_pixel(x + 5, y + 5, BinaryColor::On);
    // 时针向 12 点
    Line::new(Point::new(x + 5, y + 5), Point::new(x + 5, y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 分针向 3 点
    Line::new(Point::new(x + 5, y + 5), Point::new(x + 8, y + 5))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
}

/// 绘制高识别度科技感 HUD 雷达图标 (15x15)
fn draw_radar_icon(x: i32, y: i32, display: &mut FrameDisplay) {
    // 外圈雷达轮廓
    Circle::new(Point::new(x, y), 15)
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 内圈距离刻度圈
    Circle::new(Point::new(x + 3, y + 3), 9)
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 中心发射源实心点
    Circle::new(Point::new(x + 6, y + 6), 3)
        .draw_styled(&PrimitiveStyle::with_fill(BinaryColor::On), display)
        .unwrap();
    // 扫描波指针线（向右上）
    Line::new(Point::new(x + 7, y + 7), Point::new(x + 12, y + 3))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    // 十字刻度线
    Line::new(Point::new(x + 7, y), Point::new(x + 7, y + 2))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    Line::new(Point::new(x + 7, y + 12), Point::new(x + 7, y + 14))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    Line::new(Point::new(x, y + 7), Point::new(x + 2, y + 7))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
    Line::new(Point::new(x + 12, y + 7), Point::new(x + 14, y + 7))
        .draw_styled(&PrimitiveStyle::with_stroke(BinaryColor::On, 1), display)
        .unwrap();
}

pub(crate) fn quota_reset_label(resets_at_epoch_seconds: i64, now_epoch_seconds: i64) -> String {
    let seconds = resets_at_epoch_seconds
        .saturating_sub(now_epoch_seconds)
        .max(0);
    let total_minutes = (seconds + 59) / 60;
    let days = total_minutes / 1_440;
    let hours = total_minutes % 1_440 / 60;
    let minutes = total_minutes % 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}天"));
    }
    if days > 0 || hours > 0 {
        parts.push(format!("{hours}小时"));
    }
    parts.push(format!("{minutes}分"));
    format!("重置 {}", parts.join(" "))
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
                        reset_credits: 0,
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
}
