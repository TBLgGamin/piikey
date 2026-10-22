use super::*;
use crate::ui::activity;

fn masked(host: &str, proxies: &[&str]) -> Event {
    Event::Masked {
        host: host.into(),
        exe: Some("chrome.exe".into()),
        proxies: proxies.iter().map(|&p| p.to_owned()).collect(),
    }
}

/// Issues proxies for `texts` the way the proxy does, one text after the other (a batch
/// is stored sorted, not in text order); returns them oldest first.
fn issue(rig: &Rig, texts: &[&str]) -> Result<Vec<String>, String> {
    let engine = rig.controller.engine();
    for text in texts {
        engine
            .run(piikey::detect::Mode::Anonymize, &[text])
            .describe()?;
    }
    let view = engine.vault().read().describe()?;
    let mut proxies: Vec<String> = view.newest_first().map(|(_, _, p)| p.to_owned()).collect();
    proxies.reverse();
    Ok(proxies)
}

/// A query for `text` alone.
fn text(text: &str) -> KeyedQuery {
    KeyedQuery {
        text: text.to_owned(),
        ..KeyedQuery::default()
    }
}

#[test]
fn the_home_list_shows_where_values_went() -> Test {
    let rig = rig(true, quiet())?;
    let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
    rig.controller
        .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
    rig.controller.record(&Event::Restored {
        host: "claude.ai".into(),
        count: 4,
    });
    let snap = rig.controller.snapshot();
    assert_eq!(snap.issued, 2);
    // The sent email first, though the phone is newer; then the phone, never sent.
    let email = snap.recent.first().ok_or("no recent")?;
    assert_eq!(email.original, "jan.jansen@acme.nl");
    let sent = email.sent.as_ref().ok_or("the email was sent")?;
    assert_eq!(
        (sent.host.as_str(), sent.exe.as_deref()),
        ("chatgpt.com", Some("chrome.exe"))
    );
    let phone = snap.recent.get(1).ok_or("no phone")?;
    assert_eq!(phone.kind, EntityKind::Phone);
    assert_eq!(phone.sent, None);
    assert_eq!(
        snap.last_activity.map(|a| a.host).as_deref(),
        Some("claude.ai")
    );
    Ok(())
}

#[test]
fn keyed_values_filter_by_text_and_kind_newest_first() -> Test {
    let rig = rig(true, quiet())?;
    issue(
        &rig,
        &[
            "jan.jansen@acme.nl",
            "piet@acme.nl",
            "kees@example.org",
            "+31 6 12345678",
        ],
    )?;
    let acme = rig.controller.keyed(&text("ACME"), 1);
    assert_eq!(acme.matched, 2);
    assert_eq!(acme.items.len(), 1, "capped at the limit");
    assert!(acme.items[0].original.contains("acme"));
    let phone_query = KeyedQuery {
        kind: Some(EntityKind::Phone),
        ..KeyedQuery::default()
    };
    let phones = rig.controller.keyed(&phone_query, 10);
    assert_eq!(phones.matched, 1);
    assert_eq!(phones.items[0].kind, EntityKind::Phone);
    // The proxy is searchable too.
    let proxy = phones.items[0].proxy.clone();
    assert_eq!(rig.controller.keyed(&text(&proxy), 10).matched, 1);
    assert_eq!(rig.controller.keyed(&text("nobody"), 10).matched, 0);
    Ok(())
}

#[test]
fn a_value_keyed_long_ago_comes_first_once_it_is_sent_again() -> Test {
    let rig = rig(true, quiet())?;
    let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
    // The email is the older record; sending it again puts it on top.
    rig.controller
        .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
    let first = |items: &[Keyed]| items.first().map(|k| k.original.clone());
    let all = rig.controller.keyed(&KeyedQuery::default(), 10);
    assert_eq!(first(&all.items).as_deref(), Some("jan.jansen@acme.nl"));
    assert_eq!(all.matched, 2, "the never-sent phone is still listed");
    assert_eq!(
        first(&rig.controller.snapshot().recent).as_deref(),
        Some("jan.jansen@acme.nl")
    );
    assert_eq!(all.sites, ["chatgpt.com"]);
    Ok(())
}

#[test]
fn keyed_values_filter_by_site_and_search_finds_sites() -> Test {
    let rig = rig(true, quiet())?;
    let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
    rig.controller
        .record(&masked("chat.openai.com", &[proxies[0].as_str()]));
    rig.controller
        .record(&masked("claude.ai", &[proxies[1].as_str()]));
    let site = |site: &str| KeyedQuery {
        site: Some(site.to_owned()),
        ..KeyedQuery::default()
    };
    // A subdomain counts for its site; never-sent values do not show under a site.
    let openai = rig.controller.keyed(&site("openai.com"), 10);
    assert_eq!(openai.matched, 1);
    assert_eq!(openai.items[0].original, "jan.jansen@acme.nl");
    assert_eq!(rig.controller.keyed(&site("penai.com"), 10).matched, 0);
    // The search box matches the site and the program.
    let claude = rig.controller.keyed(&text("CLAUDE"), 10);
    assert_eq!(claude.matched, 1);
    assert_eq!(claude.items[0].kind, EntityKind::Phone);
    assert_eq!(rig.controller.keyed(&text("chrome"), 10).matched, 2);
    assert_eq!(
        rig.controller.keyed(&KeyedQuery::default(), 10).sites,
        ["claude.ai", "chat.openai.com"]
    );
    Ok(())
}

#[test]
fn the_feed_is_loaded_at_start_filtered_by_time_and_saved_at_shutdown() -> Test {
    let dir = TempDir::new()?;
    let vault = dir.0.join("vault.pkv");
    let engine = Engine::open(&vault).describe()?;
    engine
        .run(
            piikey::detect::Mode::Anonymize,
            &["mail jan.jansen@acme.nl"],
        )
        .describe()?;
    let proxy = {
        let view = engine.vault().read().describe()?;
        view.newest_first()
            .next()
            .map(|(_, _, p)| p.to_owned())
            .ok_or("nothing issued")?
    };
    let three_days_ago = activity::now() - 3 * 864_000_000_000;
    let mut loaded_activity = Activity::default();
    loaded_activity.record(&proxy, "claude.ai", None, three_days_ago);
    let fake = Arc::new(Fake {
        vault: vault.clone(),
        loaded_activity,
        ..Fake::default()
    });
    let inventory = fake.open_inventory()?;
    let watch = fake.open_watch()?;
    let controller = Controller::new(
        Box::new(Arc::clone(&fake)),
        vault,
        quiet(),
        engine,
        inventory,
        watch,
        None,
    )?;
    let period = |period: Period| KeyedQuery {
        period,
        ..KeyedQuery::default()
    };
    let week = controller.keyed(&period(Period::Week), 10);
    assert_eq!(week.matched, 1);
    let sent = week.items[0].sent.as_ref().ok_or("not sent")?;
    assert_eq!(sent.host, "claude.ai");
    assert_eq!(controller.keyed(&period(Period::Today), 10).matched, 0);
    // Saved when anything changed.
    controller.record(&masked("chatgpt.com", &[proxy.as_str()]));
    controller.shutdown();
    let saved = fake
        .saved_activity
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .last()
        .cloned()
        .ok_or("nothing saved")?;
    let saved = Activity::parse(&saved);
    let latest = saved.iter().next().ok_or("empty")?;
    assert_eq!((latest.host.as_str(), latest.count), ("chatgpt.com", 2));
    Ok(())
}

#[test]
fn forgetting_removes_vault_records() -> Test {
    let rig = rig(true, quiet())?;
    issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
    rig.run(Command::Refresh)?;
    assert_eq!(rig.controller.snapshot().issued, 2);
    rig.run(Command::Forget(vec!["jan.jansen@acme.nl".to_owned()]))?;
    assert_eq!(rig.controller.snapshot().issued, 1);
    assert_eq!(rig.controller.keyed(&text("jan.jansen"), 10).matched, 0);
    assert_eq!(rig.controller.keyed(&text("6 12345678"), 10).matched, 1);
    rig.run(Command::Forget(vec!["+31 6 12345678".to_owned()]))?;
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.issued, 0);
    assert!(snapshot.recent.is_empty());
    Ok(())
}

#[test]
fn forgetting_a_value_forgets_where_it_went() -> Test {
    let rig = rig(true, quiet())?;
    let proxies = issue(&rig, &["mail jan.jansen@acme.nl"])?;
    rig.controller
        .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
    let all = KeyedQuery::default();
    assert_eq!(rig.controller.keyed(&all, 10).sites, ["chatgpt.com"]);

    rig.run(Command::Forget(vec!["jan.jansen@acme.nl".to_owned()]))?;
    let page = rig.controller.keyed(&all, 10);
    assert!(page.sites.is_empty(), "no value is left that went anywhere");

    // The same value typed anew gets the same stand-in, and no history.
    assert_eq!(issue(&rig, &["mail jan.jansen@acme.nl"])?, proxies);
    let page = rig.controller.keyed(&all, 10);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].sent, None);

    // Nor does the saved feed keep the old life.
    rig.controller.shutdown();
    let saved = rig
        .fake
        .saved_activity
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .last()
        .cloned()
        .ok_or("nothing saved")?;
    assert!(!saved.contains(proxies[0].as_str()), "{saved}");
    Ok(())
}

#[test]
fn the_home_list_stops_at_its_size_and_issued_counts_every_record() -> Test {
    let rig = rig(true, quiet())?;
    let texts: Vec<String> = (0..RECENT + 3)
        .map(|n| format!("mail person{n}@acme.nl"))
        .collect();
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    issue(&rig, &texts)?;
    rig.run(Command::Refresh)?;
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.issued, u64::try_from(RECENT + 3).describe()?);
    assert_eq!(snapshot.recent.len(), RECENT);
    let newest = format!("person{}@acme.nl", RECENT + 2);
    assert_eq!(snapshot.recent[0].original, newest);
    Ok(())
}
