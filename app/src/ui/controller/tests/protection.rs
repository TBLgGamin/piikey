use super::*;

#[test]
fn launching_with_the_app_saved_off_gives_windows_its_proxy_back() -> Test {
    let launched = launch(true, false, |_| {})?;
    // Windows first, before the vault is even opened; the app itself stays off.
    assert_eq!(
        launched.fake.calls(),
        ["disable_system_proxy", "open_engine", "ca_installed"]
    );
    let snapshot = launched.controller()?.snapshot();
    assert!(!snapshot.enabled);
    assert_eq!(snapshot.notice, None);
    Ok(())
}

#[test]
fn a_failed_restore_at_launch_is_reported_and_the_app_still_starts() -> Test {
    let launched = launch(true, false, |fake| fail(&fake.fail_disable))?;
    let notice = launched
        .controller()?
        .snapshot()
        .notice
        .ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(notice.text.contains("registry"), "{}", notice.text);
    Ok(())
}

#[test]
fn launching_with_the_app_saved_on_resumes_it_without_restoring_first() -> Test {
    let launched = launch(true, true, |_| {})?;
    assert_eq!(
        launched.fake.calls(),
        [
            "open_engine",
            "ca_installed",
            "ensure_ca",
            "ca_installed",
            "load_model",
            "start_proxy",
            "enable_system_proxy",
            "start_capture",
            "save_policy"
        ]
    );
    let controller = launched.controller()?;
    assert!(controller.snapshot().enabled && controller.policy().enabled);
    assert_eq!(controller.snapshot().notice, None);
    Ok(())
}

#[test]
fn a_resume_without_the_certificate_gives_windows_its_proxy_back() -> Test {
    let launched = launch(false, true, |_| {})?;
    assert_eq!(
        launched.fake.calls(),
        [
            "open_engine",
            "ca_installed",
            "ensure_ca",
            "ca_installed",
            "release_model",
            "disable_system_proxy",
            "save_policy"
        ]
    );
    let controller = launched.controller()?;
    let snapshot = controller.snapshot();
    assert!(!snapshot.enabled && !controller.policy().enabled);
    assert_eq!(snapshot.notice.map(|n| n.severity), Some(Severity::Warning));
    Ok(())
}

#[test]
fn a_resume_whose_proxy_will_not_start_gives_windows_its_proxy_back() -> Test {
    let launched = launch(true, true, |fake| fail(&fake.fail_start))?;
    assert_eq!(
        launched.fake.calls(),
        [
            "open_engine",
            "ca_installed",
            "ensure_ca",
            "ca_installed",
            "load_model",
            "start_proxy",
            "release_model",
            "disable_system_proxy",
            "save_policy"
        ]
    );
    let controller = launched.controller()?;
    assert!(!controller.snapshot().enabled && !controller.policy().enabled);
    let notice = controller.snapshot().notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(notice.text.contains("port in use"), "{}", notice.text);
    Ok(())
}

#[test]
fn a_failed_restore_after_a_failed_resume_keeps_the_cause() -> Test {
    let launched = launch(true, true, |fake| {
        fail(&fake.fail_start);
        fail(&fake.fail_disable);
    })?;
    let notice = launched
        .controller()?
        .snapshot()
        .notice
        .ok_or("no notice")?;
    assert!(notice.text.contains("port in use"), "{}", notice.text);
    assert!(notice.text.contains("registry"), "{}", notice.text);
    Ok(())
}

#[test]
fn a_vault_that_will_not_open_still_gives_windows_its_proxy_back() -> Test {
    // Saved off: restored once, up front.
    let off = launch(true, false, |fake| fail(&fake.fail_engine))?;
    assert_eq!(off.fake.calls(), ["disable_system_proxy", "open_engine"]);
    assert!(off.failure()?.contains("vault locked"));
    // Saved on: nothing will start the app, so it is restored after the failure.
    let on = launch(true, true, |fake| fail(&fake.fail_engine))?;
    assert_eq!(on.fake.calls(), ["open_engine", "disable_system_proxy"]);
    assert!(on.failure()?.contains("vault locked"));
    Ok(())
}

#[test]
fn notices_follow_their_cause() {
    assert_eq!(follow(None, "B.").text, "B.");
    assert_eq!(follow(Some(Notice::warning("A")), "B.").text, "A. B.");
    assert_eq!(follow(Some(Notice::warning("A.")), "B.").text, "A. B.");
}

#[test]
fn turning_on_starts_the_proxy_then_points_windows_at_it() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    assert_eq!(
        rig.calls(),
        [
            "ensure_ca",
            "ca_installed",
            "load_model",
            "start_proxy",
            "enable_system_proxy",
            "start_capture",
            "save_policy"
        ]
    );
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.enabled && rig.live());
    assert_eq!(snapshot.cert, Cert::Installed);
    assert_eq!(snapshot.notice, None);
    assert_eq!(snapshot.busy, None);
    Ok(())
}

#[test]
fn a_capture_that_cannot_start_leaves_protection_on_and_warns() -> Test {
    let rig = rig(true, quiet())?;
    fail(&rig.fake.fail_capture);
    rig.run(Command::SetEnabled(true))?;
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.enabled && rig.live(), "protection stays on");
    let notice = snapshot.notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert!(notice.text.contains("no uia"), "{}", notice.text);
    // There is nothing to stop afterwards.
    rig.forget_calls();
    rig.run(Command::SetEnabled(false))?;
    assert_eq!(
        rig.calls(),
        [
            "disable_system_proxy",
            "stop_proxy",
            "release_model",
            "save_policy"
        ]
    );
    Ok(())
}

#[test]
fn a_capture_warning_follows_the_model_warning() -> Test {
    let rig = rig(true, quiet())?;
    fail(&rig.fake.fail_load);
    fail(&rig.fake.fail_capture);
    rig.run(Command::SetEnabled(true))?;
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.enabled);
    let notice = snapshot.notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert!(
        notice.text.contains("no gpu") && notice.text.contains("no uia"),
        "{}",
        notice.text
    );
    Ok(())
}

#[test]
fn capture_runs_only_while_the_app_is_on() -> Test {
    let rig = rig(true, quiet())?;
    let count = |call: &str| rig.calls().iter().filter(|c| *c == call).count();
    rig.run(Command::SetEnabled(true))?;
    assert_eq!((count("start_capture"), count("stop_capture")), (1, 0));
    rig.run(Command::SetEnabled(false))?;
    assert_eq!((count("start_capture"), count("stop_capture")), (1, 1));
    rig.run(Command::SetEnabled(true))?;
    assert_eq!((count("start_capture"), count("stop_capture")), (2, 1));
    // Turning on again does not start a second one.
    rig.run(Command::SetEnabled(true))?;
    assert_eq!((count("start_capture"), count("stop_capture")), (2, 1));
    Ok(())
}

#[test]
fn turning_on_without_the_certificate_only_warns() -> Test {
    let rig = rig(false, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    assert_eq!(rig.calls(), ["ensure_ca", "ca_installed", "release_model"]);
    let snapshot = rig.controller.snapshot();
    assert!(!snapshot.enabled && !rig.live());
    assert_eq!(snapshot.cert, Cert::Missing);
    assert_eq!(snapshot.notice.map(|n| n.severity), Some(Severity::Warning));
    Ok(())
}

#[test]
fn a_proxy_that_will_not_start_leaves_everything_off() -> Test {
    let rig = rig(true, quiet())?;
    rig.fake.fail_start.store(true, Ordering::Relaxed);
    rig.run(Command::SetEnabled(true))?;
    assert!(!rig.controller.snapshot().enabled && !rig.live());
    assert!(!rig.calls().contains(&"enable_system_proxy".to_owned()));
    assert!(!rig.calls().contains(&"start_capture".to_owned()));
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(notice.text.contains("port in use"));
    Ok(())
}

#[test]
fn a_windows_failure_stops_the_proxy_again() -> Test {
    let rig = rig(true, quiet())?;
    rig.fake.fail_enable.store(true, Ordering::Relaxed);
    rig.run(Command::SetEnabled(true))?;
    assert!(!rig.controller.snapshot().enabled && !rig.live());
    assert!(rig.calls().ends_with(&[
        "enable_system_proxy".to_owned(),
        "stop_proxy".to_owned(),
        "release_model".to_owned()
    ]));
    assert!(!rig.calls().contains(&"start_capture".to_owned()));
    Ok(())
}

#[test]
fn turning_off_restores_windows_before_stopping_the_proxy() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    rig.forget_calls();
    rig.run(Command::SetEnabled(false))?;
    assert_eq!(
        rig.calls(),
        [
            "disable_system_proxy",
            "stop_proxy",
            "stop_capture",
            "release_model",
            "save_policy"
        ]
    );
    assert!(!rig.controller.snapshot().enabled && !rig.live());
    Ok(())
}

#[test]
fn turning_off_keeps_the_app_when_windows_cannot_be_restored() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    rig.fake.fail_disable.store(true, Ordering::Relaxed);
    rig.forget_calls();
    rig.run(Command::SetEnabled(false))?;
    assert_eq!(rig.calls(), ["disable_system_proxy"]);
    assert!(rig.controller.snapshot().enabled && rig.live());
    assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
    Ok(())
}

#[test]
fn a_proxy_error_turns_the_app_off() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    rig.forget_calls();
    let events = rig
        .fake
        .events
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or("proxy never started")?;
    events
        .send(Event::Error("runtime panicked".into()))
        .describe()?;
    // The event thread records the error, then queues the stop on the worker.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while rig.controller.snapshot().enabled {
        if std::time::Instant::now() > deadline {
            return Err("the app never turned off".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(rig.controller.wait_idle(Duration::from_secs(20)));
    assert_eq!(
        rig.calls(),
        [
            "disable_system_proxy",
            "stop_proxy",
            "stop_capture",
            "release_model",
            "save_policy"
        ]
    );
    assert!(!rig.live());
    let notice = rig.notice().ok_or("no notice")?;
    assert!(notice.text.contains("runtime panicked"));
    Ok(())
}

#[test]
fn installing_the_certificate_updates_its_state() -> Test {
    let rig = rig(false, quiet())?;
    rig.run(Command::Refresh)?;
    assert_eq!(rig.controller.snapshot().cert, Cert::Missing);
    rig.run(Command::InstallCertificate)?;
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.cert, Cert::Installed);
    assert_eq!(snapshot.notice, None);
    Ok(())
}

#[test]
fn the_saved_wish_does_not_turn_the_live_flag_on() -> Test {
    let rig = rig(
        true,
        Policy {
            enabled: true,
            ..quiet()
        },
    )?;
    assert!(!rig.live() && !rig.controller.snapshot().enabled);
    Ok(())
}

#[test]
fn shutdown_gives_windows_its_settings_back() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    rig.forget_calls();
    rig.controller.shutdown();
    assert_eq!(
        rig.calls(),
        ["disable_system_proxy", "stop_proxy", "stop_capture"]
    );
    // Commands after shutdown are ignored.
    rig.controller.submit(Command::SetEnabled(true));
    assert!(rig.calls().len() == 3 && rig.controller.wait_idle(Duration::from_secs(5)));
    Ok(())
}

#[test]
fn shutdown_stops_the_local_api() -> Test {
    let rig = rig(
        true,
        Policy {
            http_api: true,
            ..quiet()
        },
    )?;
    rig.run(Command::Startup)?;
    assert!(rig.controller.snapshot().http);
    rig.forget_calls();
    rig.controller.shutdown();
    assert!(has_call(&rig, "stop_http"));
    assert!(!rig.controller.snapshot().http);
    Ok(())
}
