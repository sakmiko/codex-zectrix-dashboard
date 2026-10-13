use codex_zectrix_dashboard::{
    DisplayConfig, ObservedDashboardState, ObservedQuota, ObservedQuotaWindow, RadarDisplayState,
    render_dashboard,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_797_000_000;
    let output = render_dashboard(
        ObservedDashboardState {
            quota: ObservedQuota {
                windows: vec![
                    ObservedQuotaWindow {
                        name: "5 小时".into(),
                        used_percent: 31,
                        resets_at_epoch_seconds: now + 3 * 60 * 60 + 15 * 60,
                    },
                    ObservedQuotaWindow {
                        name: "7 天".into(),
                        used_percent: 58,
                        resets_at_epoch_seconds: now + 3 * 24 * 60 * 60 + 18 * 60 * 60,
                    },
                ],
                reset_credits: 0,
                stale: false,
            },
            radar: RadarDisplayState::ActiveWatch {
                forecast_window: "未来 24 小时".into(),
                reset_chance_percent: Some(72),
                stale: false,
            },
        },
        now,
        DisplayConfig::default(),
    )?;

    output.frame.write_png("preview.png")?;
    Ok(())
}
