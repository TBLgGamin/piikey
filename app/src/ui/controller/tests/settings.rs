use piikey::{detect::KindSet, policy::SettingsPatch};

use super::*;

#[test]
fn a_kind_edit_persists_and_reaches_the_engine() -> Test {
    let rig = rig(true, quiet())?;
    let email = |on| {
        Command::Edit(Edit::Kind {
            kind: EntityKind::Email,
            on,
        })
    };
    rig.run(email(false))?;
    assert_eq!(rig.calls(), ["save_policy"]);
    assert_eq!(rig.fake.last_saved()?.disabled_kinds, [EntityKind::Email]);
    assert_eq!(
        rig.controller.engine().enabled(),
        KindSet::ALL.without(EntityKind::Email)
    );
    assert_eq!(
        rig.controller.snapshot().policy.disabled_kinds,
        [EntityKind::Email]
    );
    rig.run(email(true))?;
    assert_eq!(rig.calls(), ["save_policy", "save_policy"]);
    assert!(rig.fake.last_saved()?.disabled_kinds.is_empty());
    assert_eq!(rig.controller.engine().enabled(), KindSet::ALL);
    rig.run(email(true))?;
    assert_eq!(rig.calls().len(), 2, "repeating an edit saves nothing");
    Ok(())
}

#[test]
fn a_failed_save_leaves_the_old_settings_and_engine() -> Test {
    let rig = rig(true, quiet())?;
    let before = rig.controller.engine();
    rig.fake.fail_save.store(true, Ordering::Relaxed);
    rig.run(Command::Edit(Edit::Site {
        site: "example.com".into(),
        on: true,
    }))?;
    assert!(Arc::ptr_eq(&before, &rig.controller.engine()));
    assert!(rig.controller.snapshot().policy.sites.is_empty());
    assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
    Ok(())
}

#[test]
fn a_failed_save_leaves_the_enabled_kinds_alone() -> Test {
    let rig = rig(true, quiet())?;
    rig.fake.fail_save.store(true, Ordering::Relaxed);
    rig.run(Command::Edit(Edit::Kind {
        kind: EntityKind::Email,
        on: false,
    }))?;
    assert_eq!(rig.controller.engine().enabled(), KindSet::ALL);
    assert!(rig.controller.snapshot().policy.disabled_kinds.is_empty());
    assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
    Ok(())
}

#[test]
fn saved_kinds_reach_the_engine_at_startup() -> Test {
    let policy = Policy {
        disabled_kinds: vec![EntityKind::Email],
        ..quiet()
    };
    let expected = KindSet::ALL.without(EntityKind::Email);
    assert_eq!(
        rig(true, policy.clone())?.controller.engine().enabled(),
        expected
    );
    let launched = launch_with(true, policy, |_| {})?;
    assert_eq!(launched.controller()?.engine().enabled(), expected);
    Ok(())
}

#[test]
fn site_edits_reach_the_policy_the_proxy_reads() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::Edit(Edit::Site {
        site: "Example.COM".into(),
        on: true,
    }))?;
    rig.run(Command::Edit(Edit::Program {
        exe: "Chrome".into(),
        on: true,
    }))?;
    assert_eq!(rig.controller.policy().sites, ["example.com"]);
    assert_eq!(rig.controller.policy().programs, ["chrome.exe"]);
    rig.run(Command::Edit(Edit::Site {
        site: "example.com".into(),
        on: false,
    }))?;
    assert!(rig.controller.policy().sites.is_empty());
    // A repeated add changes nothing, so nothing is saved.
    rig.forget_calls();
    rig.run(Command::Edit(Edit::Program {
        exe: "chrome.exe".into(),
        on: true,
    }))?;
    assert!(rig.calls().is_empty());
    Ok(())
}

#[test]
fn the_local_api_follows_its_switch() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::Edit(Edit::HttpApi(true)))?;
    assert_eq!(rig.calls(), ["save_policy", "start_http(7980)"]);
    assert!(rig.controller.snapshot().http);
    rig.forget_calls();
    rig.run(Command::Edit(Edit::HttpApi(false)))?;
    assert_eq!(rig.calls(), ["save_policy", "stop_http"]);
    assert!(!rig.controller.snapshot().http);
    Ok(())
}

#[test]
fn a_new_port_restarts_the_local_api() -> Test {
    let rig = rig(
        true,
        Policy {
            http_api: true,
            ..quiet()
        },
    )?;
    rig.run(Command::Startup)?;
    rig.forget_calls();
    let patch = SettingsPatch {
        http_port: Some(8123),
        ..SettingsPatch::default()
    };
    rig.run(Command::Settings(patch))?;
    assert_eq!(
        rig.calls(),
        ["save_policy", "stop_http", "start_http(8123)"]
    );
    rig.forget_calls();
    // A new token is a restart too, but only while it runs.
    rig.run(Command::RestartHttp)?;
    assert_eq!(rig.calls(), ["stop_http", "start_http(8123)"]);
    Ok(())
}

#[test]
fn a_new_token_restarts_the_local_api_and_reading_one_does_not() -> Test {
    let rig = rig(
        true,
        Policy {
            http_api: true,
            ..quiet()
        },
    )?;
    rig.run(Command::Startup)?;
    rig.forget_calls();
    assert_eq!(rig.controller.token(false)?, "test-token");
    assert!(rig.controller.wait_idle(Duration::from_secs(20)));
    assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    // The server keeps the token it started with: only a new one needs it started again.
    rig.controller.token(true)?;
    assert!(rig.controller.wait_idle(Duration::from_secs(20)));
    assert_eq!(rig.calls(), ["stop_http", "start_http(7980)"]);
    Ok(())
}

#[test]
fn a_local_api_that_will_not_start_says_why() -> Test {
    let rig = rig(true, quiet())?;
    fail(&rig.fake.fail_http);
    rig.run(Command::Edit(Edit::HttpApi(true)))?;
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(
        notice.text.contains("127.0.0.1:7980") && notice.text.contains("port in use"),
        "{}",
        notice.text
    );
    assert!(!rig.controller.snapshot().http);
    // Nothing runs, so nothing restarts.
    rig.forget_calls();
    rig.run(Command::RestartHttp)?;
    assert!(rig.calls().is_empty());
    Ok(())
}

#[test]
fn the_explorer_menu_follows_its_switch() -> Test {
    let rig = rig(
        true,
        Policy {
            explorer_menu: true,
            ..quiet()
        },
    )?;
    rig.run(Command::Edit(Edit::ExplorerMenu(false)))?;
    assert_eq!(rig.calls(), ["save_policy", "set_explorer_menu(false)"]);
    rig.forget_calls();
    rig.run(Command::Edit(Edit::ExplorerMenu(true)))?;
    assert_eq!(rig.calls(), ["save_policy", "set_explorer_menu(true)"]);
    fail(&rig.fake.fail_menu);
    rig.run(Command::Edit(Edit::ExplorerMenu(false)))?;
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(notice.text.contains("registry"), "{}", notice.text);
    Ok(())
}

#[test]
fn the_highlight_runs_capture_and_the_shortcut_and_the_model() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::Edit(Edit::Highlight(Highlight::Always)))?;
    assert_eq!(
        rig.calls(),
        [
            "save_policy",
            "start_capture",
            "set_hotkey(true)",
            "load_model"
        ]
    );
    let purpose = &rig.controller.shared.purpose;
    assert_eq!(purpose.highlight(), Highlight::Always);
    assert!(
        !purpose.mask(),
        "protection is off: nothing is kept for the proxy"
    );
    rig.forget_calls();
    rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
    assert_eq!(
        rig.calls(),
        ["save_policy", "set_hotkey(true)", "load_model"]
    );
    rig.forget_calls();
    rig.run(Command::Edit(Edit::Highlight(Highlight::Off)))?;
    assert_eq!(
        rig.calls(),
        [
            "save_policy",
            "stop_capture",
            "set_hotkey(false)",
            "release_model"
        ]
    );
    assert_eq!(rig.controller.shared.purpose.highlight(), Highlight::Off);
    Ok(())
}

#[test]
fn capture_serves_protection_and_the_highlight_together() -> Test {
    let rig = rig(
        true,
        Policy {
            highlight: Highlight::Always,
            ..quiet()
        },
    )?;
    rig.run(Command::Startup)?;
    let count = |call: &str| rig.calls().iter().filter(|c| *c == call).count();
    assert_eq!(count("start_capture"), 1);
    assert!(!rig.controller.shared.purpose.mask());
    rig.run(Command::SetEnabled(true))?;
    assert_eq!(count("start_capture"), 1, "capture runs already");
    assert!(rig.controller.shared.purpose.mask());
    rig.forget_calls();
    rig.run(Command::SetEnabled(false))?;
    // The proxy stops; capture and the model stay for the highlight.
    assert_eq!(
        rig.calls(),
        [
            "disable_system_proxy",
            "stop_proxy",
            "load_model",
            "save_policy"
        ]
    );
    assert!(!rig.controller.shared.purpose.mask());
    Ok(())
}

#[test]
fn a_field_that_cannot_be_read_turns_the_highlight_into_a_notice() -> Test {
    let rig = rig(true, quiet())?;
    fail(&rig.fake.fail_capture);
    rig.run(Command::Edit(Edit::Highlight(Highlight::Always)))?;
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert!(notice.text.contains("no uia"), "{}", notice.text);
    Ok(())
}

#[test]
fn a_taken_shortcut_is_said_in_a_notice() -> Test {
    let rig = rig(true, quiet())?;
    fail(&rig.fake.fail_hotkey);
    rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert!(notice.text.contains("Ctrl+Alt+P"), "{}", notice.text);
    Ok(())
}

#[test]
fn startup_brings_the_saved_features_up() -> Test {
    let rig = rig(
        true,
        Policy {
            highlight: Highlight::Hotkey,
            explorer_menu: true,
            http_api: true,
            ..quiet()
        },
    )?;
    rig.run(Command::Startup)?;
    assert_eq!(
        rig.calls(),
        [
            "set_explorer_menu(true)",
            "start_http(7980)",
            "start_capture",
            "set_hotkey(true)",
            "load_model"
        ]
    );
    assert!(rig.controller.snapshot().http);
    Ok(())
}

#[test]
fn settings_from_the_api_apply_as_a_whole() -> Test {
    let rig = rig(true, quiet())?;
    let patch = SettingsPatch {
        sites: Some(vec!["Example.com".into()]),
        http_api: Some(true),
        ..SettingsPatch::default()
    };
    rig.run(Command::Settings(patch))?;
    assert_eq!(rig.controller.policy().sites, ["example.com"]);
    assert_eq!(rig.calls(), ["save_policy", "start_http(7980)"]);
    // One bad value and nothing changes.
    rig.forget_calls();
    let bad = SettingsPatch {
        sites: Some(vec!["not a site".into()]),
        http_api: Some(false),
        ..SettingsPatch::default()
    };
    rig.run(Command::Settings(bad))?;
    assert!(rig.calls().is_empty());
    assert!(rig.controller.policy().http_api);
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(notice.text.contains("not a site"), "{}", notice.text);
    // Nothing to change, nothing saved.
    rig.run(Command::Settings(SettingsPatch::default()))?;
    assert!(rig.calls().is_empty());
    Ok(())
}

#[test]
fn a_pause_of_the_highlight_reaches_the_snapshot_and_wakes_the_window() -> Test {
    let rig = rig(true, quiet())?;
    let before = rig.controller.snapshot();
    assert!(!before.highlight_paused && !rig.controller.highlight_paused());
    rig.controller.shared.purpose.set_paused(true);
    let after = rig
        .controller
        .wait_changed(before.version, Duration::from_secs(20))
        .ok_or("the pause did not wake the window")?;
    assert!(after.highlight_paused && rig.controller.highlight_paused());
    rig.controller.shared.purpose.set_paused(false);
    assert!(!rig.controller.snapshot().highlight_paused);
    Ok(())
}
