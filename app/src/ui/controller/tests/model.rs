use super::*;
use crate::ui::controller::model::SKIPPED_TEXT;

#[test]
fn a_launch_without_the_model_downloads_it_then_turns_on() -> Test {
    let launched = launch(true, true, |fake| fail(&fake.model_missing))?;
    let controller = launched.controller()?;
    let snapshot = wait_for(controller, |s| s.model == Model::Ready && s.enabled)?;
    assert_eq!(snapshot.notice, None);
    let calls = launched.fake.calls();
    // Windows gets its settings back for the download, which comes before the proxy.
    assert_eq!(
        calls.first().map(String::as_str),
        Some("disable_system_proxy")
    );
    let at = |call: &str| calls.iter().position(|c| c == call);
    let (fetch, load, start) = (at("fetch_model"), at("load_model"), at("start_proxy"));
    assert!(fetch.is_some() && fetch < load && load < start, "{calls:?}");
    Ok(())
}

#[test]
fn a_failed_download_leaves_the_app_off() -> Test {
    let launched = launch(true, true, |fake| {
        fail(&fake.model_missing);
        fail(&fake.fetch_fails);
    })?;
    let controller = launched.controller()?;
    let snapshot = wait_for(controller, |s| matches!(s.model, Model::Failed(_)))?;
    assert_eq!(snapshot.model, Model::Failed("offline".into()));
    assert!(!snapshot.enabled);
    assert!(!launched.fake.calls().iter().any(|c| c == "start_proxy"));
    Ok(())
}

#[test]
fn going_on_without_the_model_warns_and_masks_patterns_only() -> Test {
    let launched = launch(true, false, |fake| {
        fail(&fake.model_missing);
        fail(&fake.fetch_fails);
    })?;
    let controller = launched.controller()?;
    wait_for(controller, |s| matches!(s.model, Model::Failed(_)))?;
    controller.submit(Command::SkipModel);
    let snapshot = wait_for(controller, |s| s.model == Model::Skipped)?;
    let notice = snapshot.notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert_eq!(notice.text, SKIPPED_TEXT);
    // Turning on now starts without loading a model.
    controller.submit(Command::SetEnabled(true));
    let snapshot = wait_for(controller, |s| s.enabled)?;
    assert!(snapshot.enabled);
    assert!(!launched.fake.calls().iter().any(|c| c == "load_model"));
    Ok(())
}

#[test]
fn going_on_without_the_model_while_a_saved_on_waits_still_warns() -> Test {
    let launched = launch(true, true, |fake| {
        fail(&fake.model_missing);
        fail(&fake.fetch_fails);
    })?;
    let controller = launched.controller()?;
    wait_for(controller, |s| matches!(s.model, Model::Failed(_)))?;
    controller.submit(Command::SkipModel);
    // The saved "on" is honoured now, with the patterns alone, and the user is told so.
    let snapshot = wait_for(controller, |s| s.enabled && s.model == Model::Skipped)?;
    let notice = snapshot
        .notice
        .ok_or("the user must hear the model is not used")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert_eq!(notice.text, SKIPPED_TEXT);
    Ok(())
}

#[test]
fn the_model_stays_loaded_while_the_highlight_needs_it() -> Test {
    let rig = rig(true, quiet())?;
    rig.run(Command::SetEnabled(true))?;
    rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
    rig.forget_calls();
    rig.run(Command::SetEnabled(false))?;
    assert!(
        !has_call(&rig, "release_model"),
        "the highlight needs it: {:?}",
        rig.calls()
    );
    rig.run(Command::Edit(Edit::Highlight(Highlight::Off)))?;
    assert!(has_call(&rig, "release_model"));
    Ok(())
}

#[test]
fn a_model_that_arrives_while_the_highlight_waits_is_loaded() -> Test {
    let launched = launch_with(
        true,
        Policy {
            highlight: Highlight::Always,
            ..quiet()
        },
        |fake| fail(&fake.model_missing),
    )?;
    let controller = launched.controller()?;
    wait_for(controller, |s| s.model == Model::Ready)?;
    eventually("the model to load", || {
        launched.fake.calls().iter().any(|c| c == "load_model")
    })
}

#[test]
fn a_sync_that_waited_for_the_model_acts_on_the_settings_of_the_moment() -> Test {
    let rig = rig(
        true,
        Policy {
            highlight: Highlight::Always,
            ..quiet()
        },
    )?;
    let held = rig.controller.model_sync.lock().describe()?;
    let controller = Arc::clone(&rig.controller);
    let sync = thread::spawn(move || controller.sync_model());
    // By now the sync waits for the lock, which a load or release of the model holds.
    thread::sleep(Duration::from_millis(200));
    // What was running meanwhile switched the highlight off: nothing needs the model any more.
    rig.controller.shared.policy.write().describe()?.highlight = Highlight::Off;
    drop(held);
    sync.join().map_err(|_| "the sync panicked".to_owned())?;
    assert_eq!(rig.calls(), ["release_model"]);
    Ok(())
}
