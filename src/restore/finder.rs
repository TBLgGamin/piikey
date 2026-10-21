//! The vault's own lookup of proxies, which a [`Restorer`](super::Restorer) takes into its pass.

use crate::{
    detect::Mode,
    engine::{Engine, Replacement},
};

/// The most a stream holds back for the engine's lookup. A proxy longer than this (a JWT) can be
/// missed when it straddles two chunks: holding a whole token back would stall every stream for
/// the sake of one rare value.
const MAX_REACH: usize = 1024;

/// Finds the proxies the vault issued in a text, whatever the scope of a [`Restorer`] says.
///
/// A restorer asks it for the proxies of the whole vault and restores them together with its own
/// scope in one pass over the same text. Two passes one after the other would read what the
/// first wrote: a value that is equal to a proxy issued for another value, which the first pass
/// restored, would be restored again by the second.
///
/// What it finds must follow from the bytes around it alone: at most one byte before it and a
/// few after it. That is what lets a stream be cut between two proxies and give what one pass
/// over the whole text would.
pub trait ProxyFinder: Sync {
    /// The length in bytes of the longest proxy [`ProxyFinder::find`] can report, `0` when there
    /// is none to find, which lets a restorer skip the lookup. A stream holds back that much of
    /// its end, so that a proxy still arriving is not cut in two.
    fn longest(&self) -> usize;

    /// What each proxy in `text` stands for: sorted by position, none overlapping another.
    fn find(&self, text: &[u8]) -> Vec<Replacement>;
}

/// Finds nothing: a restorer then restores its scope only.
impl ProxyFinder for () {
    fn longest(&self) -> usize {
        0
    }

    fn find(&self, _text: &[u8]) -> Vec<Replacement> {
        Vec::new()
    }
}

/// The proxies the engine's vault issued, of any kind, as [`Engine::plan`] finds them for
/// deanonymizing.
impl ProxyFinder for Engine {
    /// Capped at 1 KiB, see [`MAX_REACH`].
    fn longest(&self) -> usize {
        self.vault()
            .read()
            .map_or(MAX_REACH, |view| view.longest_proxy().min(MAX_REACH))
    }

    /// Text that is not UTF-8 is looked through stretch by stretch; the bytes between the
    /// stretches stay as they are. What the vault cannot say (a poisoned lock) is not found: a
    /// response must not fail for it.
    fn find(&self, text: &[u8]) -> Vec<Replacement> {
        let mut stretches = Vec::new();
        let mut offsets = Vec::new();
        let mut at = 0;
        for chunk in text.utf8_chunks() {
            offsets.push(at);
            stretches.push(chunk.valid());
            at += chunk.valid().len() + chunk.invalid().len();
        }
        let Ok(plans) = Engine::plan(self, Mode::Deanonymize, &stretches) else {
            return Vec::new();
        };
        plans
            .into_iter()
            .zip(offsets)
            .flat_map(|(plan, offset)| {
                plan.into_iter().map(move |rep| Replacement {
                    start: rep.start + offset,
                    end: rep.end + offset,
                    with: rep.with,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REACH, ProxyFinder};
    use crate::{
        Result,
        detect::{EntityKind, Mode},
        engine::Engine,
        restore::{Restorer, Scope, ScopeEntry},
        testing::temp_dir,
    };

    fn engine() -> Result<Engine> {
        Engine::open(&temp_dir("finder").join("vault.pkv"))
    }

    /// The stand-in the vault holds for an email.
    fn proxy_of(engine: &Engine, original: &str) -> Result<String> {
        let masked = engine.run(Mode::Anonymize, &[original])?;
        Ok(masked[0].clone())
    }

    /// The stand-in the vault holds for a person.
    fn stand_in_for(engine: &Engine, name: &str) -> Result<String> {
        engine
            .vault()
            .resolve(vec![(EntityKind::Person, name.into())], &|_, _| false)?;
        let view = engine.vault().read()?;
        let Some(stand_in) = view.proxy_for(EntityKind::Person, name) else {
            panic!("no stand-in for {name}");
        };
        Ok(stand_in.to_owned())
    }

    #[test]
    fn the_engine_finds_its_proxies_at_their_offsets_around_bytes_that_are_not_utf8() -> Result<()>
    {
        let engine = engine()?;
        let original = "jan.jansen@acme.nl";
        let proxy = proxy_of(&engine, original)?;
        assert_ne!(proxy, original);

        let mut text = b"\xFF\xFE".to_vec();
        text.extend_from_slice(proxy.as_bytes());
        text.extend_from_slice(b" \x80 and ");
        let second = text.len();
        text.extend_from_slice(proxy.as_bytes());
        let found = engine.find(&text);

        let spans: Vec<(usize, usize, &str)> = found
            .iter()
            .map(|rep| (rep.start, rep.end, &*rep.with))
            .collect();
        assert_eq!(
            spans,
            [
                (2, 2 + proxy.len(), original),
                (second, second + proxy.len(), original)
            ]
        );
        Ok(())
    }

    #[test]
    fn the_engine_reaches_as_far_as_the_longest_proxy_up_to_a_limit() -> Result<()> {
        let engine = engine()?;
        assert_eq!(engine.longest(), 0, "an empty vault has nothing to find");
        assert!(engine.find(b"jan.jansen@acme.nl").is_empty());

        let proxy = proxy_of(&engine, "jan.jansen@acme.nl")?;
        assert_eq!(engine.longest(), proxy.len());

        // A token as long as a JWT: its stand-in is as long, and the lookup holds back only so
        // much for it.
        let long = format!("AKIA{}", "A".repeat(3000));
        engine
            .vault()
            .resolve(vec![(EntityKind::Secret, long.into())], &|_, _| false)?;
        assert_eq!(engine.longest(), MAX_REACH);
        Ok(())
    }

    #[test]
    fn a_name_equal_to_a_stand_in_comes_back_as_itself_in_one_pass_with_the_engine() -> Result<()> {
        let engine = engine()?;
        // The vault gave `Jan Smit` a stand-in, and then somebody who really has that name one
        // of her own: text equal to an earlier stand-in is masked like any other value.
        let first = stand_in_for(&engine, "Jan Smit")?;
        let second = stand_in_for(&engine, &first)?;
        let reply = format!("{first} and {second}");
        let want = format!("Jan Smit and {first}");

        // The conversation sent only the first; the vault knows both.
        let scope = || {
            Scope::from_pairs([ScopeEntry {
                kind: EntityKind::Person,
                proxy: first.as_str().into(),
                original: "Jan Smit".into(),
            }])
        };
        let restorer = Restorer::new(scope())?;
        assert_eq!(
            restorer.restore_with(reply.as_bytes(), &engine),
            want.as_bytes()
        );
        let mut stream = Restorer::new(scope())?;
        let mut out = Vec::new();
        for chunk in reply.as_bytes().chunks(3) {
            out.extend(stream.feed_with(chunk, &engine));
        }
        out.extend(stream.flush_with(&engine));
        assert_eq!(out, want.as_bytes());
        assert_eq!(stream.restored_count(), 2);

        // The vault's pass and then the scope's read what the first wrote: the name comes back
        // as the person the stand-in was issued for.
        let vault_first = engine.run(Mode::Deanonymize, &[&reply])?;
        assert_eq!(vault_first[0], want);
        assert_eq!(
            restorer.restore_with(vault_first[0].as_bytes(), &()),
            b"Jan Smit and Jan Smit"
        );
        Ok(())
    }
}
