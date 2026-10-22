//! The live highlight: an outline around each piece of personal data in the text field in focus,
//! and the Ctrl+Alt+P shortcut that asks for it.
//!
//! Capture (`crate::capture`) is the one reader of the focused field. It decides when outlines are
//! due and tells the [`Overlay`] where: [`Overlay::show`] with the rectangles of the values on the
//! screen (or the field's own, when its text control cannot say where a value is),
//! [`Overlay::hide`] when they are gone. "Open at this place" draws the same way
//! ([`Overlay::flash`]); both find the rectangles with `crate::uia_text`. The overlay draws four
//! thin bars around each rectangle: windows that stay on top of everything, take no clicks and no
//! focus, in the brand colour of the theme (green for the flash that says a field holds nothing).
//! Nothing is drawn inside the rectangle and nothing about the text reaches this module.
//!
//! `windows-reactor` has no such window and raw Win32 calls are `unsafe`, which is forbidden here,
//! so winit makes the windows and softbuffer fills them. winit allows one event loop per process
//! and it must run on a thread of its own: [`Overlay::get_or_start`] starts it once, on first need,
//! and it is never started again. The shortcut is registered on that same thread (a Win32 message
//! loop must run on the thread that owns the hotkey window) by `global-hotkey`.
//!
//! Capture says where the outlines go every time it looks at the focus. A request that is not
//! repeated within [`STALE`] therefore means capture stopped, stalled or died, and the outlines go.
//!
//! [`Overlay::flash`] is for outlines that nothing asks for again, such as the one that shows
//! where "Open at this place" put a value: they stay for the time they are given and go by
//! themselves.

use std::{
    num::NonZeroU32,
    rc::Rc,
    sync::{Arc, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use global_hotkey::{
    GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState,
    hotkey::{Code, HotKey, Modifiers},
};
use softbuffer::{Context, Surface};
use winit::{
    application::ApplicationHandler,
    dpi::{PhysicalPosition, PhysicalSize},
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy, OwnedDisplayHandle},
    platform::windows::{EventLoopBuilderExtWindows, HWND, WindowAttributesExtWindows},
    raw_window_handle::{HasWindowHandle, RawWindowHandle},
    window::{Window, WindowId, WindowLevel},
};

use crate::{Res, proxy::Purpose, ui::assets::system_dark};

/// Pixels between a field and its outline.
const GAP: i32 = 2;
/// Pixels the outline is thick.
const THICK: i32 = 3;
/// Pixels from a field to the far side of its outline.
const EDGE: i32 = GAP + THICK;
/// The smallest and the largest side of what counts as a text field, in pixels: Windows reports
/// zero-sized and screen-sized rectangles for elements that are not on screen. The text of a value
/// can be smaller than a field, down to [`MIN_TEXT_SIDE`].
const MIN_SIDE: i32 = 8;
const MIN_TEXT_SIDE: i32 = 2;
const MAX_SIDE: i32 = 16_384;
/// The largest coordinate of such a rectangle; Windows parks hidden windows near -32000.
const MAX_COORD: u32 = 100_000;
/// The bars of one outline: top, bottom, left, right.
const BARS: usize = 4;
/// The most outlines at once. Each is [`BARS`] windows, made when first needed.
const MAX_OUTLINES: usize = 8;
/// Where a bar waits while it is made: Windows parks hidden windows near here, and nothing is
/// there to see.
const PARKED: i32 = -32_000;
/// How long an outline stays without capture asking for it again.
const STALE: Duration = Duration::from_secs(3);
/// How long [`Overlay::set_hotkey`] waits for the overlay thread.
const ANSWER: Duration = Duration::from_secs(5);

/// What the user is told when the shortcut cannot be registered.
const HOTKEY_TAKEN: &str =
    "Ctrl+Alt+P is used by another program; highlighting works in Always mode only.";
const STOPPED: &str = "the highlight overlay is not running";

/// A rectangle on the screen in physical pixels. `right` and `bottom` lie outside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    /// The rectangle of a text field; `None` for one that cannot be a field in view: empty, a
    /// sliver, bigger than any screen, or far off it.
    pub(crate) fn field(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        Self::sized(left, top, right, bottom, MIN_SIDE)
    }

    /// The rectangle if no side is shorter than `least` or longer than [`MAX_SIDE`] and all four
    /// edges are within [`MAX_COORD`] of the origin.
    fn sized(left: i32, top: i32, right: i32, bottom: i32, least: i32) -> Option<Self> {
        let sides = [right.checked_sub(left)?, bottom.checked_sub(top)?];
        let plausible = sides.iter().all(|side| (least..=MAX_SIDE).contains(side))
            && [left, top, right, bottom]
                .iter()
                .all(|coordinate| coordinate.unsigned_abs() <= MAX_COORD);
        plausible.then_some(Self {
            left,
            top,
            right,
            bottom,
        })
    }

    /// The rectangle of the text of a value, which can be small: a short value in small type is
    /// not eight pixels wide. `None` for one that cannot be in view: empty, a hair, bigger than any
    /// screen, or far off it.
    pub(crate) fn text(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        Self::sized(left, top, right, bottom, MIN_TEXT_SIDE)
    }

    /// How far it reaches across.
    pub(crate) fn width(self) -> i32 {
        self.right.saturating_sub(self.left)
    }

    /// How far it reaches down.
    pub(crate) fn height(self) -> i32 {
        self.bottom.saturating_sub(self.top)
    }

    /// The same rectangle `dx` pixels further across and `dy` further down.
    pub(crate) fn shifted(self, dx: i32, dy: i32) -> Self {
        Self {
            left: self.left.saturating_add(dx),
            top: self.top.saturating_add(dy),
            right: self.right.saturating_add(dx),
            bottom: self.bottom.saturating_add(dy),
        }
    }

    fn intersects(self, other: Self) -> bool {
        self.left < other.right
            && other.left < self.right
            && self.top < other.bottom
            && other.top < self.bottom
    }
}

/// What an outline says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// The field holds personal data.
    Pii,
    /// The field holds none: the green flash that answers the shortcut.
    Clean,
}

/// The colour of an outline as `0x00RRGGBB`: the brand colour of the theme (`#6f49b1` on light,
/// `#d6c9f9` on dark) for personal data, a green that reads on both for a clean field.
const fn color(mark: Mark, dark: bool) -> u32 {
    match (mark, dark) {
        (Mark::Pii, false) => 0x006f_49b1,
        (Mark::Pii, true) => 0x00d6_c9f9,
        (Mark::Clean, false) => 0x002e_7d32,
        (Mark::Clean, true) => 0x0081_c995,
    }
}

/// Where one bar goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Place {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

/// The four bars of the outline of `field`: top, bottom, left, right. They do not overlap each
/// other and leave [`GAP`] pixels around the field. Bars that would lie outside `screen` are moved
/// onto it and cut to fit, so a field that fills its window still gets an outline, on its edge.
/// `None` when the field is not on the screen at all.
fn outline(field: Rect, screen: Option<Rect>) -> Option<[Place; BARS]> {
    // A screen without an area tells nothing.
    let screen = screen.filter(|screen| screen.right > screen.left && screen.bottom > screen.top);
    if screen.is_some_and(|screen| !field.intersects(screen)) {
        return None;
    }
    let (x0, y0) = (field.left - EDGE, field.top - EDGE);
    let (x1, y1) = (field.right + EDGE, field.bottom + EDGE);
    let (wide, high) = (x1 - x0, y1 - y0 - 2 * THICK);
    let bars = [
        (x0, y0, wide, THICK),
        (x0, y1 - THICK, wide, THICK),
        (x0, y0 + THICK, THICK, high),
        (x1 - THICK, y0 + THICK, THICK, high),
    ];
    let mut places = [Place {
        x: 0,
        y: 0,
        width: 1,
        height: 1,
    }; BARS];
    for (place, (x, y, width, height)) in places.iter_mut().zip(bars) {
        let (x, y, width, height) = match screen {
            Some(screen) => {
                let width = width.min(screen.right - screen.left);
                let height = height.min(screen.bottom - screen.top);
                (
                    x.clamp(screen.left, screen.right - width),
                    y.clamp(screen.top, screen.bottom - height),
                    width,
                    height,
                )
            }
            None => (x, y, width, height),
        };
        *place = Place {
            x,
            y,
            width: u32::try_from(width).ok().filter(|&side| side > 0)?,
            height: u32::try_from(height).ok().filter(|&side| side > 0)?,
        };
    }
    Some(places)
}

/// The outlines of `fields`, each its own four bars, for the ones that are on `screen`, and no more
/// than [`MAX_OUTLINES`] of them: more would be a screen full of frames.
fn outlines(fields: &[Rect], screen: Option<Rect>) -> Vec<[Place; BARS]> {
    fields
        .iter()
        .filter_map(|&field| outline(field, screen))
        .take(MAX_OUTLINES)
        .collect()
}

/// What the capture thread and the thread that registers the shortcut ask of the overlay thread.
enum Cmd {
    Show {
        fields: Vec<Rect>,
        mark: Mark,
    },
    Flash {
        fields: Vec<Rect>,
        mark: Mark,
        how_long: Duration,
    },
    Hide,
    Hotkey {
        on: bool,
        answer: mpsc::Sender<Res<()>>,
    },
}

/// The highlight overlay. One per process: see [`Overlay::get_or_start`].
#[derive(Debug)]
pub(crate) struct Overlay {
    events: EventLoopProxy<Cmd>,
}

// A failed start is kept: winit cannot create a second event loop in the process.
static OVERLAY: OnceLock<Res<Overlay>> = OnceLock::new();

impl Overlay {
    /// The overlay, started on its own thread the first time this is called. `purpose` is the one
    /// of the process: the overlay counts the presses of the shortcut on it ([`Purpose::press`]); a
    /// later call with another one changes nothing.
    ///
    /// # Errors
    /// The thread, the event loop or the windows cannot be made. The message is for the user, and
    /// every later call returns it again.
    pub(crate) fn get_or_start(purpose: &Arc<Purpose>) -> Res<&'static Self> {
        OVERLAY
            .get_or_init(|| Self::start(Arc::clone(purpose)))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The overlay if it has been started and runs.
    pub(crate) fn get() -> Option<&'static Self> {
        OVERLAY.get().and_then(|overlay| overlay.as_ref().ok())
    }

    /// Hides the outline, if the overlay runs. Capture calls it when it ends.
    pub(crate) fn hide_any() {
        if let Some(overlay) = Self::get() {
            overlay.hide();
        }
    }

    fn start(purpose: Arc<Purpose>) -> Res<Self> {
        let (ready, started) = mpsc::channel();
        thread::Builder::new()
            .name("piikey-highlight".to_owned())
            .spawn(move || run(purpose, &ready))
            .map_err(|error| format!("piikey could not start the highlight overlay: {error}"))?;
        match started.recv() {
            Ok(Ok(events)) => Ok(Self { events }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("the highlight overlay ended before it started".to_owned()),
        }
    }

    /// Outlines each of `fields` in the colour of `mark`; the same request again keeps the outlines
    /// up.
    pub(crate) fn show(&self, fields: &[Rect], mark: Mark) {
        // An overlay that is gone shows nothing: capture goes on without it.
        let _ = self.events.send_event(Cmd::Show {
            fields: fields.to_vec(),
            mark,
        });
    }

    /// Outlines each of `fields` in the colour of `mark` for `how_long`, then takes the outlines
    /// away by themselves: for an outline that nothing asks for again, such as the one that shows
    /// where a value was found. Other outlines, or [`Overlay::hide`], replace it sooner.
    pub(crate) fn flash(&self, fields: &[Rect], mark: Mark, how_long: Duration) {
        // An overlay that is gone shows nothing.
        let _ = self.events.send_event(Cmd::Flash {
            fields: fields.to_vec(),
            mark,
            how_long,
        });
    }

    /// Takes the outline away.
    pub(crate) fn hide(&self) {
        let _ = self.events.send_event(Cmd::Hide);
    }

    /// Registers the shortcut (Ctrl+Alt+P) with Windows, or gives it back. Each press counts on the
    /// [`Purpose`]. Registering twice is fine.
    ///
    /// # Errors
    /// Another program has the shortcut, or Windows refused it. The message is for the user.
    pub(crate) fn set_hotkey(&self, on: bool) -> Res<()> {
        let (answer, reply) = mpsc::channel();
        self.events
            .send_event(Cmd::Hotkey { on, answer })
            .map_err(|_| STOPPED.to_owned())?;
        reply.recv_timeout(ANSWER).map_err(|_| STOPPED.to_owned())?
    }
}

/// The overlay thread: the event loop, until the process ends.
fn run(purpose: Arc<Purpose>, ready: &mpsc::Sender<Res<EventLoopProxy<Cmd>>>) {
    let event_loop = match EventLoop::<Cmd>::with_user_event()
        .with_any_thread(true)
        // The process's DPI setting is the app's: winit must not change it under WinUI.
        .with_dpi_aware(false)
        .build()
    {
        Ok(event_loop) => event_loop,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "piikey could not start the highlight overlay: {error}"
            )));
            return;
        }
    };
    let key = shortcut();
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == key.id() && event.state == HotKeyState::Pressed {
            purpose.press();
        }
    }));
    let mut bars = Bars {
        ready: Some((ready.clone(), event_loop.create_proxy())),
        windows: None,
        shown: None,
        hotkey: None,
    };
    // Ends with the process: nothing closes these windows.
    let _ = event_loop.run_app(&mut bars);
}

/// Ctrl+Alt+P.
fn shortcut() -> HotKey {
    HotKey::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyP)
}

/// What the overlay thread answers [`Overlay::start`] with, and the proxy it answers through.
type Ready = (mpsc::Sender<Res<EventLoopProxy<Cmd>>>, EventLoopProxy<Cmd>);

/// The handler of the overlay thread.
struct Bars {
    /// Answers [`Overlay::start`] once the windows exist.
    ready: Option<Ready>,
    windows: Option<Windows>,
    /// The outlines that are up, and when they go unless they are asked for again.
    shown: Option<Shown>,
    hotkey: Option<Hotkey>,
}

/// The shortcut with Windows. The manager owns a hidden window, so it lives and dies on the thread
/// that runs the message loop.
struct Hotkey {
    manager: GlobalHotKeyManager,
    registered: bool,
}

impl ApplicationHandler<Cmd> for Bars {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let Some((ready, events)) = self.ready.take() else {
            return;
        };
        match Windows::create(event_loop) {
            Ok(windows) => {
                self.windows = Some(windows);
                let _ = ready.send(Ok(events));
            }
            Err(error) => {
                let _ = ready.send(Err(format!(
                    "piikey could not make the highlight outline: {error}"
                )));
                event_loop.exit();
            }
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, cmd: Cmd) {
        match cmd {
            Cmd::Show { fields, mark } => self.show(event_loop, &fields, mark, STALE),
            Cmd::Flash {
                fields,
                mark,
                how_long,
            } => self.show(event_loop, &fields, mark, how_long),
            Cmd::Hide => self.hide(),
            Cmd::Hotkey { on, answer } => {
                let _ = answer.send(self.set_hotkey(on));
            }
        }
    }

    fn window_event(&mut self, _: &ActiveEventLoop, window: WindowId, event: WindowEvent) {
        // Windows asks a window to draw itself again when it was covered or moved.
        if event == WindowEvent::RedrawRequested
            && let Some(windows) = &mut self.windows
            && let Some(bar) = windows
                .bars
                .iter_mut()
                .find(|bar| bar.window.id() == window)
            && let Some(color) = bar.color
        {
            bar.paint(color);
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        match due(
            self.shown.as_ref().map(|shown| shown.hide_at),
            Instant::now(),
        ) {
            Due::Now => {
                self.hide();
                event_loop.set_control_flow(ControlFlow::Wait);
            }
            Due::At(at) => event_loop.set_control_flow(ControlFlow::WaitUntil(at)),
            Due::Nothing => event_loop.set_control_flow(ControlFlow::Wait),
        }
    }
}

impl Bars {
    /// Outlines `fields`, each of its own, and takes the outlines away `stays` from now, unless
    /// they are asked for again.
    fn show(&mut self, event_loop: &ActiveEventLoop, fields: &[Rect], mark: Mark, stays: Duration) {
        let hide_at = deadline(Instant::now(), stays);
        if refresh(&mut self.shown, fields, mark, hide_at) {
            return;
        }
        let Some(windows) = &mut self.windows else {
            return;
        };
        let places = outlines(fields, screen(event_loop));
        if places.is_empty() {
            self.hide();
            return;
        }
        // An outline there are no bars for is left out: the bars that exist are drawn.
        let _ = windows.grow(event_loop, places.len());
        let color = color(mark, system_dark());
        let mut drawn = 0;
        for (bars, places) in windows.bars.chunks_exact_mut(BARS).zip(&places) {
            for (bar, place) in bars.iter_mut().zip(places) {
                bar.put(*place, color);
            }
            drawn += 1;
        }
        // The outlines that are no more go away.
        for bar in windows.bars.iter().skip(drawn * BARS) {
            bar.window.set_visible(false);
        }
        self.shown = Some(Shown {
            fields: fields.to_vec(),
            mark,
            hide_at,
        });
    }

    fn hide(&mut self) {
        if let Some(windows) = &self.windows {
            windows.hide();
        }
        self.shown = None;
    }

    fn set_hotkey(&mut self, on: bool) -> Res<()> {
        if !on {
            if let Some(hotkey) = &mut self.hotkey
                && hotkey.registered
            {
                hotkey.registered = false;
                hotkey
                    .manager
                    .unregister(shortcut())
                    .map_err(|error| format!("could not give back Ctrl+Alt+P: {error}"))?;
            }
            return Ok(());
        }
        if self.hotkey.as_ref().is_some_and(|hotkey| hotkey.registered) {
            return Ok(());
        }
        let hotkey = match self.hotkey.take() {
            Some(hotkey) => hotkey,
            None => Hotkey {
                manager: GlobalHotKeyManager::new()
                    .map_err(|error| format!("could not listen for Ctrl+Alt+P: {error}"))?,
                registered: false,
            },
        };
        let registered = hotkey.manager.register(shortcut());
        self.hotkey = Some(Hotkey {
            registered: registered.is_ok(),
            ..hotkey
        });
        registered.map_err(|error| match error {
            global_hotkey::Error::AlreadyRegistered(_) => HOTKEY_TAKEN.to_owned(),
            other => format!("could not register Ctrl+Alt+P: {other}"),
        })
    }
}

/// When an outline that is asked for at `now` to stay `stays` goes. A time that cannot be added
/// ends the outline at once.
fn deadline(now: Instant, stays: Duration) -> Instant {
    now.checked_add(stays).unwrap_or(now)
}

/// The outlines that are up: where, in which colour, and when they go unless they are asked for
/// again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    fields: Vec<Rect>,
    mark: Mark,
    hide_at: Instant,
}

/// Keeps the outlines that are up when they are the ones asked for: `fields` in the colour of
/// `mark`. Their end moves to `hide_at` then, and the answer is `true`; `false` when `shown` is no
/// outline or other ones, which are then to be drawn.
fn refresh(shown: &mut Option<Shown>, fields: &[Rect], mark: Mark, hide_at: Instant) -> bool {
    if let Some(up) = shown
        && up.mark == mark
        && up.fields == fields
    {
        up.hide_at = hide_at;
        return true;
    }
    false
}

/// What the overlay thread does about the outline that is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    /// None is up.
    Nothing,
    /// Its time is up.
    Now,
    /// It goes at this time.
    At(Instant),
}

/// What is due for an outline that goes at `hide_at`, seen at `now`.
fn due(hide_at: Option<Instant>, now: Instant) -> Due {
    match hide_at {
        None => Due::Nothing,
        Some(at) if at <= now => Due::Now,
        Some(at) => Due::At(at),
    }
}

/// All the screens as one rectangle; `None` when Windows reports none.
fn screen(event_loop: &ActiveEventLoop) -> Option<Rect> {
    event_loop
        .available_monitors()
        .map(|monitor| {
            let (at, size) = (monitor.position(), monitor.size());
            Rect {
                left: at.x,
                top: at.y,
                right: at
                    .x
                    .saturating_add(i32::try_from(size.width).unwrap_or(i32::MAX)),
                bottom: at
                    .y
                    .saturating_add(i32::try_from(size.height).unwrap_or(i32::MAX)),
            }
        })
        .reduce(|all, one| Rect {
            left: all.left.min(one.left),
            top: all.top.min(one.top),
            right: all.right.max(one.right),
            bottom: all.bottom.max(one.bottom),
        })
}

/// The bars of every outline, [`BARS`] to an outline, and the hidden window that owns them. An
/// owned window is not on the taskbar and not in Alt+Tab, which slivers would otherwise be. The
/// bars of one outline are made at the start, the others when an outline first needs them.
struct Windows {
    bars: Vec<Bar>,
    context: Context<OwnedDisplayHandle>,
    owner: HWND,
    // Dropped last: the bars are owned by it.
    _window: Window,
}

impl Windows {
    fn create(event_loop: &ActiveEventLoop) -> Res<Self> {
        let context = Context::new(event_loop.owned_display_handle())
            .map_err(|error| format!("no display: {error}"))?;
        let window = event_loop
            .create_window(
                Window::default_attributes()
                    .with_title("piikey highlight")
                    .with_decorations(false)
                    .with_resizable(false)
                    .with_visible(false)
                    .with_active(false)
                    .with_skip_taskbar(true)
                    .with_drag_and_drop(false)
                    .with_inner_size(PhysicalSize::new(1, 1)),
            )
            .map_err(|error| format!("cannot make a window: {error}"))?;
        let owner = owner_handle(&window)?;
        let mut windows = Self {
            bars: Vec::new(),
            context,
            owner,
            _window: window,
        };
        windows.grow(event_loop, 1)?;
        Ok(windows)
    }

    /// Makes bars until there are enough for `outlines` outlines.
    fn grow(&mut self, event_loop: &ActiveEventLoop, outlines: usize) -> Res<()> {
        while self.bars.len() < outlines * BARS {
            let bar = Bar::create(event_loop, &self.context, self.owner)?;
            self.bars.push(bar);
        }
        Ok(())
    }

    /// Hides every bar.
    fn hide(&self) {
        for bar in &self.bars {
            bar.window.set_visible(false);
        }
    }
}

/// The Windows handle of `window`, for the windows it owns.
fn owner_handle(window: &Window) -> Res<HWND> {
    match window
        .window_handle()
        .map_err(|error| format!("no window handle: {error}"))?
        .as_raw()
    {
        RawWindowHandle::Win32(handle) => Ok(handle.hwnd.get()),
        other => Err(format!("not a Windows window: {other:?}")),
    }
}

/// One bar of the outline.
struct Bar {
    window: Rc<Window>,
    surface: Surface<OwnedDisplayHandle, Rc<Window>>,
    /// What it was last filled with.
    color: Option<u32>,
}

impl Bar {
    fn create(
        event_loop: &ActiveEventLoop,
        context: &Context<OwnedDisplayHandle>,
        owner: HWND,
    ) -> Res<Self> {
        let window = Rc::new(
            event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title("piikey highlight")
                        .with_decorations(false)
                        .with_resizable(false)
                        .with_window_level(WindowLevel::AlwaysOnTop)
                        // No activation: the field in focus keeps the focus.
                        .with_active(false)
                        .with_visible(false)
                        .with_drag_and_drop(false)
                        .with_owner_window(owner)
                        // Made, filled and made click-through while shown once: far from the
                        // screen, so that no dot shows at its corner meanwhile.
                        .with_position(PhysicalPosition::new(PARKED, PARKED))
                        // Windows would keep a sliver at its minimum size otherwise.
                        .with_min_inner_size(PhysicalSize::new(1, 1))
                        .with_inner_size(PhysicalSize::new(THICK.unsigned_abs(), THICK.unsigned_abs())),
                )
                .map_err(|error| format!("cannot make a window: {error}"))?,
        );
        let surface = Surface::new(context, Rc::clone(&window))
            .map_err(|error| format!("cannot draw in a window: {error}"))?;
        let mut bar = Self {
            window,
            surface,
            color: None,
        };
        // A window that takes no clicks is layered, and a layered window draws nothing that was
        // not shown first: make it click-through once it is on screen and has been filled.
        bar.paint(color(Mark::Pii, false));
        bar.window.set_visible(true);
        bar.window
            .set_cursor_hittest(false)
            .map_err(|error| format!("cannot make a window click-through: {error}"))?;
        bar.paint(color(Mark::Pii, false));
        bar.window.set_visible(false);
        Ok(bar)
    }

    /// Moves the bar to `place`, fills it with `color` and shows it.
    fn put(&mut self, place: Place, color: u32) {
        self.window
            .set_outer_position(PhysicalPosition::new(place.x, place.y));
        let _ = self
            .window
            .request_inner_size(PhysicalSize::new(place.width, place.height));
        self.paint(color);
        self.window.set_visible(true);
    }

    fn paint(&mut self, color: u32) {
        let size = self.window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return;
        };
        if self.surface.resize(width, height).is_err() {
            return;
        }
        let Ok(mut buffer) = self.surface.buffer_mut() else {
            return;
        };
        buffer.fill(color);
        if buffer.present().is_ok() {
            self.color = Some(color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// The pixels a bar covers.
    fn covers(place: Place) -> Rect {
        let right = place.x + i32::try_from(place.width).unwrap_or(i32::MAX);
        let bottom = place.y + i32::try_from(place.height).unwrap_or(i32::MAX);
        rect(place.x, place.y, right, bottom)
    }

    /// The bars of an outline as the rectangles they cover.
    fn bars(field: Rect, screen: Option<Rect>) -> Result<[Rect; 4], String> {
        outline(field, screen)
            .map(|places| places.map(covers))
            .ok_or_else(|| format!("no outline for {field:?}"))
    }

    #[test]
    fn a_field_is_a_rectangle_in_view() {
        assert!(Rect::field(100, 200, 500, 240).is_some());
        for (name, found) in [
            ("empty", Rect::field(10, 10, 10, 10)),
            ("a sliver", Rect::field(10, 10, 500, 12)),
            ("inside out", Rect::field(500, 240, 100, 200)),
            ("screen-sized and more", Rect::field(0, 0, 20_000, 900)),
            ("parked far off", Rect::field(-200_000, 0, -199_000, 40)),
            ("overflowing", Rect::field(i32::MIN, 0, i32::MAX, 40)),
        ] {
            assert_eq!(found, None, "{name}");
        }
    }

    #[test]
    fn the_outline_has_four_bars_around_the_field_with_a_gap() -> Result<(), String> {
        let field = rect(300, 400, 900, 440);
        let [top, bottom, left, right] = bars(field, None)?;
        // Three pixels thick, two from the field.
        assert_eq!((top.top, top.bottom), (field.top - EDGE, field.top - GAP));
        assert_eq!(
            (bottom.top, bottom.bottom),
            (field.bottom + GAP, field.bottom + EDGE)
        );
        assert_eq!(
            (left.left, left.right),
            (field.left - EDGE, field.left - GAP)
        );
        assert_eq!(
            (right.left, right.right),
            (field.right + GAP, field.right + EDGE)
        );
        // They close the frame: the top and bottom span it, the sides fill what is between.
        assert_eq!(
            (top.left, top.right),
            (field.left - EDGE, field.right + EDGE)
        );
        assert_eq!((left.top, left.bottom), (top.bottom, bottom.top));
        assert_eq!((right.top, right.bottom), (top.bottom, bottom.top));
        // No bar overlaps another or the field itself.
        let all = [top, bottom, left, right];
        for (index, one) in all.iter().enumerate() {
            assert!(!one.intersects(field), "bar {index} covers the field");
            for other in &all[index + 1..] {
                assert!(!one.intersects(*other), "bars overlap");
            }
        }
        Ok(())
    }

    #[test]
    fn a_field_at_the_edge_of_the_screen_keeps_its_outline_on_screen() -> Result<(), String> {
        let screen = rect(0, 0, 1920, 1080);
        // A maximized editor: the field fills the screen.
        for bar in bars(rect(0, 40, 1920, 1080), Some(screen))? {
            assert!(
                bar.left >= 0 && bar.top >= 0 && bar.right <= 1920 && bar.bottom <= 1080,
                "{bar:?} is off the screen"
            );
        }
        // A field that is not on the screen at all has no outline.
        assert_eq!(outline(rect(2000, 100, 2600, 140), Some(screen)), None);
        assert_eq!(outline(rect(-900, 100, -300, 140), Some(screen)), None);
        // Nothing to compare with: the outline goes where the field is.
        assert!(outline(rect(2000, 100, 2600, 140), None).is_some());
        Ok(())
    }

    #[test]
    fn an_outline_goes_when_its_time_is_up() {
        let now = Instant::now();
        let later = now + Duration::from_secs(2);
        assert_eq!(due(None, now), Due::Nothing);
        assert_eq!(due(Some(later), now), Due::At(later));
        // Reaching its time is enough, and so is being past it.
        assert_eq!(due(Some(later), later), Due::Now);
        assert_eq!(due(Some(now), later), Due::Now);
    }

    #[test]
    fn the_same_outlines_again_only_move_their_end() {
        let now = Instant::now();
        let later = now + STALE;
        let fields = [rect(10, 20, 300, 60), rect(40, 80, 90, 100)];
        let mut shown = None;
        // Nothing is up: there is nothing to keep.
        assert!(!refresh(&mut shown, &fields, Mark::Pii, now));
        assert_eq!(shown, None);

        let up = Shown {
            fields: fields.to_vec(),
            mark: Mark::Pii,
            hide_at: now,
        };
        shown = Some(up.clone());
        assert!(refresh(&mut shown, &fields, Mark::Pii, later));
        let moved = Shown {
            hide_at: later,
            ..up
        };
        assert_eq!(shown, Some(moved.clone()));

        // Another place, one outline more or fewer, or another mark is another outline: it has to
        // be drawn, so nothing is kept and nothing changes here.
        let mut other = fields;
        other[1].right += 1;
        assert!(!refresh(&mut shown, &other, Mark::Pii, now));
        assert!(!refresh(&mut shown, &fields[..1], Mark::Pii, now));
        assert!(!refresh(&mut shown, &fields, Mark::Clean, now));
        assert_eq!(shown, Some(moved));
    }

    #[test]
    fn every_place_gets_an_outline_of_its_own_up_to_the_most_there_are_bars_for() {
        let screen = rect(0, 0, 1920, 1080);
        let places: Vec<Rect> = (0..12)
            .map(|n| rect(100, 100 + 60 * n, 300, 130 + 60 * n))
            .collect();
        assert_eq!(outlines(&places[..3], Some(screen)).len(), 3);
        assert_eq!(outlines(&places, Some(screen)).len(), MAX_OUTLINES);
        // One that is not on the screen is left out, and does not count against the most.
        let off = rect(3000, 100, 3200, 130);
        assert_eq!(
            outlines(&[places[0], off, places[1]], Some(screen)).len(),
            2
        );
        let mut with_off = vec![off; 3];
        with_off.extend_from_slice(&places);
        assert_eq!(outlines(&with_off, Some(screen)).len(), MAX_OUTLINES);
        assert!(outlines(&[off], Some(screen)).is_empty());
        assert!(outlines(&[], Some(screen)).is_empty());
    }

    #[test]
    fn the_text_of_a_value_may_be_small_but_not_nothing() {
        // A short value in small type: well under the eight pixels that a field needs.
        assert!(Rect::text(100, 200, 112, 214).is_some());
        assert!(Rect::text(100, 200, 103, 203).is_some());
        for (name, found) in [
            ("empty", Rect::text(10, 10, 10, 10)),
            ("a hair", Rect::text(10, 10, 500, 11)),
            ("inside out", Rect::text(500, 240, 100, 200)),
            ("bigger than any screen", Rect::text(0, 0, 20_000, 900)),
            ("parked far off", Rect::text(-200_000, 0, -199_990, 14)),
        ] {
            assert_eq!(found, None, "{name}");
        }
    }

    #[test]
    fn a_flash_and_a_show_each_end_after_their_own_time() {
        let now = Instant::now();
        assert_eq!(deadline(now, STALE), now + STALE);
        assert_eq!(
            deadline(now, Duration::from_secs(2)),
            now + Duration::from_secs(2)
        );
        // A time that cannot be added ends the outline at once instead of panicking.
        assert_eq!(deadline(now, Duration::MAX), now);
    }
}
