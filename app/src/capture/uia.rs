//! [`Uia`]: the real [`Desktop`], UI Automation and the clipboard.

use std::{
    num::NonZeroU32,
    sync::{Arc, PoisonError},
};

use piikey::policy::Policy;
use uiautomation::{
    UIAutomation, UIElement, UITreeWalker,
    core::{UICacheRequest, UICondition},
    patterns::UITextPattern,
    types::{ControlType, TreeScope, UIProperty},
    variants::{Value, Variant},
};

use super::desktop::{Clip, Desktop, Field, Focus};
use crate::{highlight::Rect, process, proxy::Shared};

/// Ancestors looked at to find the page an element is in.
const PAGE_STEPS: usize = 40;
/// Characters read from a field through its text pattern; [`Typed`](crate::proxy::Typed) keeps
/// less than this anyway.
const MAX_CHARS: i32 = 1 << 18;
/// Characters of a field's value from which Chromium may have cut the rest off: it keeps 10,000.
const VALUE_CUT: usize = 10_000;

/// The real desktop: UI Automation and the clipboard.
pub(super) struct Uia {
    shared: Arc<Shared>,
    automation: UIAutomation,
    /// The control view: what a screen reader walks.
    walker: UITreeWalker,
    /// What is asked of the focused element.
    focus: UICacheRequest,
    /// The same with the element's value and place, for while a protected element has the focus, or
    /// the highlight reads every field in focus.
    focus_value: UICacheRequest,
    /// What is asked of the ancestors walked to find the page.
    ancestors: UICacheRequest,
    /// Matches text fields.
    edits: UICondition,
    /// The element that has the focus.
    current: Option<Current>,
    /// The address bar of the last browser window that needed one.
    address_bar: Option<AddressBar>,
}

/// The focused element and what was asked of it.
struct Current {
    element: UIElement,
    /// It is a password field, or that could not be told. Nothing of such an element is read: not
    /// its text, not its place.
    password: bool,
    /// Its value and its rectangle came with it.
    value_cached: bool,
    /// Whether [`Desktop::text`] has looked, and what it found: a look costs a call into the other
    /// program for some elements, and protection and highlight may both ask.
    text_read: bool,
    text: Option<String>,
}

/// A browser window's address bar, for browsers whose page element does not carry its address.
struct AddressBar {
    /// Identifies the window.
    window: Vec<i32>,
    edit: UIElement,
}

impl Uia {
    pub(super) fn new(shared: Arc<Shared>) -> uiautomation::Result<Self> {
        let automation = UIAutomation::new()?;
        let request = |properties: &[UIProperty]| -> uiautomation::Result<UICacheRequest> {
            let request = automation.create_cache_request()?;
            for &property in properties {
                request.add_property(property)?;
            }
            Ok(request)
        };
        let focus_properties = [
            UIProperty::RuntimeId,
            UIProperty::ProcessId,
            UIProperty::ControlType,
            UIProperty::IsPassword,
            UIProperty::IsValuePatternAvailable,
            UIProperty::ValueIsReadOnly,
            UIProperty::IsTextPatternAvailable,
        ];
        let focus = request(&focus_properties)?;
        let focus_value = request(
            &[
                &focus_properties[..],
                &[UIProperty::ValueValue, UIProperty::BoundingRectangle],
            ]
            .concat(),
        )?;
        let ancestors = request(&[
            UIProperty::RuntimeId,
            UIProperty::ControlType,
            UIProperty::ValueValue,
        ])?;
        let edits = automation.create_property_condition(
            UIProperty::ControlType,
            Variant::from(ControlType::Edit as i32),
            None,
        )?;
        Ok(Self {
            shared,
            walker: automation.get_control_view_walker()?,
            automation,
            focus,
            focus_value,
            ancestors,
            edits,
            current: None,
            address_bar: None,
        })
    }

    /// The host of the page `element` is in: the address its page element carries. `None` outside
    /// a page, and for pages that are not on a web host.
    fn page_host(&mut self, element: &UIElement) -> Option<String> {
        let mut below = element.clone();
        // The page was found but says nothing about its address.
        let mut nameless = false;
        for _ in 0..PAGE_STEPS {
            let parent = self
                .walker
                .get_parent_build_cache(&below, &self.ancestors)
                .ok()?;
            match parent.get_cached_control_type().ok() {
                Some(ControlType::Document) if !nameless => {
                    match cached_string(&parent, UIProperty::ValueValue) {
                        Some(address) if !address.trim().is_empty() => return host_of(&address),
                        _ => nameless = true,
                    }
                }
                Some(ControlType::Window) if nameless => return self.address_bar_host(&parent),
                _ => {}
            }
            below = parent;
        }
        None
    }

    /// The host in the first text field of a browser window: its address bar.
    fn address_bar_host(&mut self, window: &UIElement) -> Option<String> {
        let id = runtime_id(window)?;
        if let Some(bar) = self.address_bar.as_ref().filter(|bar| bar.window == id)
            && let Some(host) = value_host(&bar.edit)
        {
            return Some(host);
        }
        let edit = window
            .find_first(TreeScope::Descendants, &self.edits)
            .ok()?;
        let host = value_host(&edit)?;
        self.address_bar = Some(AddressBar { window: id, edit });
        Some(host)
    }
}

impl Desktop for Uia {
    fn focus(&mut self, with_text: bool) -> Option<Focus> {
        self.current = None;
        let request = if with_text {
            &self.focus_value
        } else {
            &self.focus
        };
        let element = self
            .automation
            .get_focused_element_build_cache(request)
            .ok()?;
        let id = runtime_id(&element)?;
        // Unreadable counts as a password: nothing is lost by leaving a field alone. It comes with
        // the element at every look, so a field that turns into a password field is noticed.
        let password = cached_bool(&element, UIProperty::IsPassword).unwrap_or(true);
        self.current = Some(Current {
            element,
            password,
            value_cached: with_text,
            text_read: false,
            text: None,
        });
        Some(Focus { id, password })
    }

    fn protected(&mut self) -> bool {
        let Some(element) = self.current.as_ref().map(|c| c.element.clone()) else {
            return false;
        };
        let policy = self
            .shared
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !policy.enabled {
            return false;
        }
        let host = if policy.sites.is_empty() {
            None
        } else {
            self.page_host(&element)
        };
        if let Some(host) = &host
            && policy.intercepts(host, None)
        {
            return true;
        }
        if policy.programs.is_empty() {
            return false;
        }
        let exe = element
            .get_cached_process_id()
            .ok()
            .and_then(|pid| u32::try_from(pid).ok())
            .and_then(process::exe_name);
        policy.intercepts(host.as_deref().unwrap_or_default(), exe.as_deref())
    }

    fn text(&mut self) -> Option<String> {
        let current = self.current.as_mut()?;
        if current.password {
            return None;
        }
        if !current.text_read {
            current.text_read = true;
            current.text = read_text(current);
        }
        current.text.clone()
    }

    fn field(&mut self) -> Option<Field> {
        let (element, cached, password) = self.current.as_ref().map(|current| {
            (
                current.element.clone(),
                current.value_cached,
                current.password,
            )
        })?;
        let own = element
            .get_cached_process_id()
            .ok()
            .and_then(|pid| u32::try_from(pid).ok())
            == Some(std::process::id());
        let hidden = password || own;
        let text = if hidden { None } else { self.text() };
        let rect = if hidden {
            None
        } else {
            bounds_of(&element, cached)
        };
        Field::of(password, own, text, rect)
    }

    fn bounds(&mut self) -> Option<Rect> {
        let current = self.current.as_ref()?;
        if current.password {
            return None;
        }
        bounds_of(&current.element, current.value_cached)
    }

    fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
        clipboard_win::seq_num()
    }

    fn clipboard_text(&mut self) -> Clip {
        // Whether there is text to read needs no open clipboard: a copy of an image or of files is
        // not worth getting in another program's way.
        if !clipboard_win::is_format_avail(clipboard_win::formats::CF_UNICODETEXT) {
            return Clip::NoText;
        }
        match clipboard_win::get_clipboard_string() {
            Ok(text) => Clip::Text(text),
            Err(_) => Clip::Busy,
        }
    }
}

/// What the user typed into the focused element: its value, or its text pattern for an editable
/// block. `None` when it is no text field, cannot be read, or is read-only.
fn read_text(current: &Current) -> Option<String> {
    let element = &current.element;
    if cached_bool(element, UIProperty::IsValuePatternAvailable) == Some(true) {
        // A page's address and a read-only field are not something the user typed.
        if cached_bool(element, UIProperty::ValueIsReadOnly) != Some(false) {
            return None;
        }
        let value = if current.value_cached {
            element.get_cached_property_value(UIProperty::ValueValue)
        } else {
            element.get_property_value(UIProperty::ValueValue)
        };
        let value = value.ok()?.get_string().ok()?;
        if value.chars().take(VALUE_CUT).count() < VALUE_CUT {
            return Some(value);
        }
        // Chromium cuts the value of a long field short; its text pattern has all of it.
        return Some(
            range_text(element)
                .filter(|text| text.len() > value.len())
                .unwrap_or(value),
        );
    }
    // An editable block (`contenteditable`) has only a text pattern. A page element has one too,
    // and holds the whole page.
    if element.get_cached_control_type().ok() == Some(ControlType::Document)
        || cached_bool(element, UIProperty::IsTextPatternAvailable) != Some(true)
    {
        return None;
    }
    range_text(element)
}

/// Where `element` is on the screen: from what came with it, or else asked for now.
fn bounds_of(element: &UIElement, cached: bool) -> Option<Rect> {
    let rect = if cached {
        element.get_cached_bounding_rectangle()
    } else {
        element.get_bounding_rectangle()
    }
    .ok()?;
    Rect::field(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    )
}

/// What identifies `element` among the elements on the desktop: the id that came with it, or else
/// the live one.
fn runtime_id(element: &UIElement) -> Option<Vec<i32>> {
    let cached = element
        .get_cached_property_value(UIProperty::RuntimeId)
        .ok()
        .and_then(|id| id.get_value().ok());
    match cached {
        Some(Value::ArrayI4(id)) => Some(id),
        _ => element.get_runtime_id().ok(),
    }
}

/// The text of `element` through its text pattern.
fn range_text(element: &UIElement) -> Option<String> {
    element
        .get_pattern::<UITextPattern>()
        .ok()?
        .get_document_range()
        .ok()?
        .get_text(MAX_CHARS)
        .ok()
}

fn cached_bool(element: &UIElement, property: UIProperty) -> Option<bool> {
    let value = element.get_cached_property_value(property).ok()?;
    let flag: Result<bool, _> = (&value).try_into();
    flag.ok()
}

fn cached_string(element: &UIElement, property: UIProperty) -> Option<String> {
    element
        .get_cached_property_value(property)
        .ok()?
        .get_string()
        .ok()
}

/// The host in the value of `element`, which is an address bar or a page element.
fn value_host(element: &UIElement) -> Option<String> {
    element
        .get_property_value(UIProperty::ValueValue)
        .ok()?
        .get_string()
        .ok()
        .and_then(|address| host_of(&address))
}

/// The host of a page's address, as a page element carries it (`https://chat.openai.com/c/1?x`) or
/// an address bar shows it (`chat.openai.com/c/1`). `None` for what is not on a web host:
/// `chrome://settings`, `file:///C:/a.html`, `about:blank`, or text that is no address.
fn host_of(address: &str) -> Option<String> {
    Policy::parse_site(address).filter(|host| !host.starts_with('*'))
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn addresses_give_their_host() {
        assert_eq!(
            host_of("https://Chat.OpenAI.com/c/abc?x=1#y").as_deref(),
            Some("chat.openai.com")
        );
        assert_eq!(
            host_of("http://localhost:3000/").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            host_of("https://user:pw@example.com:8443/p").as_deref(),
            Some("example.com")
        );
        // What an address bar shows has no scheme.
        assert_eq!(host_of("claude.ai/chat/1").as_deref(), Some("claude.ai"));
        assert_eq!(host_of("192.168.1.1/admin").as_deref(), Some("192.168.1.1"));
        for other in [
            "",
            "chrome://settings/",
            "edge://sync-confirmation-dialog/",
            "file:///C:/page.html",
            "about:blank",
            "view-source:https://example.com/",
            "two words typed in the address bar",
            "*.example.com",
        ] {
            assert_eq!(host_of(other), None, "{other}");
        }
    }
}
