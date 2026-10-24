//! The map of a dashboard: every file that holds personal data is a tile, as big as what it holds
//! and in the colour of the type it holds most of. The files of one folder lie together, so a
//! folder can be told from the space around its tiles. The layout decides which tiles there are and
//! where they lie, the widgets draw it.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use piikey::{
    detect::EntityKind,
    inventory::{Rest, Tile, Tiles},
    sys::{is_under, same_path},
};
use windows_reactor::{
    Border, Canvas, Color, FontWeight, HorizontalAlignment, PointerEventInfo, StackPanel, Stretch,
    TextBlock, TextTrimming, ThemeBrush, Thickness, TooltipExt, VerticalAlignment, View, Viewbox,
};

use super::{
    crumbs::name_of,
    palette::{NEUTRAL, kind_color, text_on},
    types,
};
use crate::ui::{
    pages::kit::{Context, counted, thousands},
    treemap::{Rect, squarify},
    window::{Dash, Msg, Origin},
};

/// How far a file's tile keeps clear of its neighbours on each side.
const TILE_INSET: f64 = 1.0;
/// How far the tiles of a folder keep clear of the tiles around it, on each side.
const FOLDER_INSET: f64 = 2.0;
/// A tile smaller than this in either direction is not drawn: it could not be seen or clicked.
const MIN_SIDE: f64 = 2.0;
/// The room a tile needs for its name: this wide and this high.
const NAME_ROOM: (f64, f64) = (64.0, 26.0);
/// The height a tile needs for its count under its name.
const COUNT_ROOM: f64 = 42.0;

/// What a tile stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Of {
    /// This file.
    File(PathBuf),
    /// The files beyond the ones that got a tile, together.
    Rest,
}

/// One tile: where it lies on the canvas and what it says.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Placed {
    pub(super) of: Of,
    pub(super) rect: Rect,
    pub(super) color: Color,
    /// The colour of its label: white or black, whichever reads better on `color`.
    pub(super) text: Color,
    /// The file's name, or `+12 files`.
    pub(super) name: String,
    /// `12 found`.
    pub(super) detail: String,
    /// All of it, for the tooltip.
    pub(super) tip: String,
}

/// What a file adds to the map: all it holds, or only what is of `kind`.
pub(super) fn weigh(counts: &[(EntityKind, u32)], hits: u64, kind: Option<EntityKind>) -> u64 {
    match kind {
        None => hits,
        Some(kind) => counts
            .iter()
            .filter(|&&(of, _)| of == kind)
            .map(|&(_, n)| u64::from(n))
            .sum(),
    }
}

/// A weight in the layout.
#[expect(
    clippy::cast_precision_loss,
    reason = "a tile's area needs no precision beyond 2^53 values"
)]
fn area_of(weight: u64) -> f64 {
    weight as f64
}

/// A file or the rest, as the layout weighs it.
struct Item {
    of: Of,
    weight: f64,
    color: Color,
    name: String,
    detail: String,
    tip: String,
}

/// The folders of the map as a tree, so the files of a folder are laid out inside one rectangle.
#[derive(Default)]
struct Folder {
    folders: BTreeMap<String, Folder>,
    /// Indices into the items.
    files: Vec<usize>,
    /// The weight of everything under it.
    weight: f64,
}

impl Folder {
    /// Puts item `index` of weight `weight` into the folder `path` leads to.
    fn insert(&mut self, path: &[String], index: usize, weight: f64) {
        self.weight += weight;
        match path.split_first() {
            None => self.files.push(index),
            Some((name, rest)) => self
                .folders
                .entry(name.clone())
                .or_default()
                .insert(rest, index, weight),
        }
    }

    /// How many things lie directly in it: files and folders.
    fn entries(&self) -> usize {
        self.files.len() + self.folders.len()
    }
}

/// Something that gets a share of a folder's rectangle.
enum Entry<'a> {
    File(usize),
    Folder(&'a Folder),
}

/// `rect` pulled in by `by` on every side; less for a rectangle too small to spare it.
fn inset(rect: Rect, by: f64) -> Rect {
    let by = by.min(rect.w / 4.0).min(rect.h / 4.0).max(0.0);
    Rect {
        x: rect.x + by,
        y: rect.y + by,
        w: rect.w - 2.0 * by,
        h: rect.h - 2.0 * by,
    }
}

/// Lays the folder out inside `rect`, the heaviest entry first.
fn lay_out(folder: &Folder, items: &[Item], rect: Rect, out: &mut Vec<Placed>) {
    let mut entries: Vec<(f64, Entry<'_>)> = folder
        .files
        .iter()
        .map(|&index| (items[index].weight, Entry::File(index)))
        .chain(
            folder
                .folders
                .values()
                .map(|inner| (inner.weight, Entry::Folder(inner))),
        )
        .collect();
    // The heaviest first makes the squarest tiles; entries of one weight keep their order.
    entries.sort_by(|a, b| b.0.total_cmp(&a.0));
    let weights: Vec<f64> = entries.iter().map(|(weight, _)| *weight).collect();
    for ((_, entry), place) in entries.into_iter().zip(squarify(&weights, rect)) {
        match entry {
            Entry::File(index) => {
                let rect = inset(place, TILE_INSET);
                if rect.w >= MIN_SIDE && rect.h >= MIN_SIDE {
                    let item = &items[index];
                    out.push(Placed {
                        of: item.of.clone(),
                        rect,
                        color: item.color,
                        text: text_on(item.color),
                        name: item.name.clone(),
                        detail: item.detail.clone(),
                        tip: item.tip.clone(),
                    });
                }
            }
            // A folder that is only a way to another one takes no room of its own.
            Entry::Folder(inner) => {
                let rect = if inner.entries() > 1 {
                    inset(place, FOLDER_INSET)
                } else {
                    place
                };
                if rect.w >= MIN_SIDE && rect.h >= MIN_SIDE {
                    lay_out(inner, items, rect, out);
                }
            }
        }
    }
}

/// The folders on the way from `at` to `file`, as the names Windows tells them apart by: letter
/// case does not count, so the files of `C:\Docs` and `c:\docs` lie in one folder. A drive and its
/// root come first when `at` is the top.
fn way(file: &Path, at: &Path) -> Vec<String> {
    let skip = if is_under(file, at) {
        at.components().count()
    } else {
        0
    };
    let names: Vec<String> = file
        .components()
        .skip(skip)
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    // Without the file's own name.
    names
        .split_last()
        .map(|(_, folders)| folders.to_vec())
        .unwrap_or_default()
}

/// `12 found`.
pub(super) fn found(hits: u64) -> String {
    format!("{} found", thousands(hits))
}

/// The item of a file, or `None` when it adds nothing to the map: no weight, or none of `kind`.
fn file_item(tile: &Tile, kind: Option<EntityKind>) -> Option<Item> {
    let hits = weigh(&tile.counts, tile.hits, kind);
    if hits == 0 {
        return None;
    }
    let color = kind.or_else(|| tile.dominant()).map_or(NEUTRAL, kind_color);
    let name = name_of(&tile.path);
    let folder = tile
        .path
        .parent()
        .map(|parent| parent.display().to_string())
        .unwrap_or_default();
    let tip = format!(
        "{name}\n{} \u{b7} {}\n{folder}",
        found(hits),
        types::summary(&tile.counts, kind, 3)
    );
    Some(Item {
        of: Of::File(tile.path.clone()),
        weight: area_of(hits),
        color,
        name,
        detail: found(hits),
        tip,
    })
}

/// The item of the files that got no tile.
fn rest_item(rest: &Rest, kind: Option<EntityKind>) -> Option<Item> {
    let hits = weigh(&rest.counts, rest.hits, kind);
    if hits == 0 || rest.files == 0 {
        return None;
    }
    let name = format!("+{}", counted(u64::from(rest.files), "file", "files"));
    Some(Item {
        of: Of::Rest,
        weight: area_of(hits),
        color: NEUTRAL,
        tip: format!(
            "{name}, the smaller ones\n{}\nOpen a folder to see them",
            found(hits)
        ),
        name,
        detail: found(hits),
    })
}

/// The tiles of `tiles` laid out inside `area`: the files below `at` in the folders they are in,
/// the heaviest first, and the files beyond the tiles as one grey tile. With a `kind` only the
/// files that hold it count, by how much of it.
pub(super) fn place(tiles: &Tiles, at: &Path, kind: Option<EntityKind>, area: Rect) -> Vec<Placed> {
    let mut items: Vec<Item> = Vec::new();
    let mut root = Folder::default();
    for tile in &tiles.tiles {
        if let Some(item) = file_item(tile, kind) {
            root.insert(&way(&tile.path, at), items.len(), item.weight);
            items.push(item);
        }
    }
    if let Some(item) = rest_item(&tiles.rest, kind) {
        root.insert(&[], items.len(), item.weight);
        items.push(item);
    }
    let mut out = Vec::with_capacity(items.len());
    lay_out(&root, &items, area, &mut out);
    out
}

/// Whether a tile has room for its name, and for its count under it.
fn label_room(rect: &Rect) -> (bool, bool) {
    let name = rect.w >= NAME_ROOM.0 && rect.h >= NAME_ROOM.1;
    (name, name && rect.h >= COUNT_ROOM)
}

/// A tile's name over its count, in the tile's label colour.
fn label(tile: &Placed, with_count: bool) -> View {
    let name = TextBlock::new()
        .text(&tile.name)
        .font_size(12.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .foreground(tile.text)
        .text_trimming(TextTrimming::CharacterEllipsis);
    if !with_count {
        return name.into();
    }
    StackPanel::new()
        .children((
            name,
            TextBlock::new()
                .text(&tile.detail)
                .font_size(11.0)
                .foreground(tile.text)
                .text_trimming(TextTrimming::CharacterEllipsis),
        ))
        .into()
}

/// What a selected file or folder looks like among the tiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Focus {
    /// Nothing is selected: every tile as it is.
    None,
    /// This tile is selected.
    Chosen,
    /// A folder is selected and the tile lies in it.
    Inside,
    /// A folder is selected and the tile lies elsewhere.
    Outside,
}

/// How the tile `of` looks given what is `selected`.
pub(super) fn focus(of: &Of, selected: Option<&Path>, folder_selected: bool) -> Focus {
    let Some(selected) = selected else {
        return Focus::None;
    };
    match of {
        Of::Rest => {
            if folder_selected {
                Focus::Outside
            } else {
                Focus::None
            }
        }
        Of::File(path) if same_path(path, selected) => Focus::Chosen,
        Of::File(path) if folder_selected && is_under(path, selected) => Focus::Inside,
        Of::File(_) if folder_selected => Focus::Outside,
        Of::File(_) => Focus::None,
    }
}

/// One tile as a bordered box on the canvas. A click selects its file.
fn tile_view(tile: &Placed, focus: Focus, context: Context<'_>) -> View {
    let ring = match focus {
        Focus::Chosen => tile.text,
        _ => Color::transparent(),
    };
    let mut border = Border::new()
        .canvas_left(tile.rect.x)
        .canvas_top(tile.rect.y)
        .width(tile.rect.w)
        .height(tile.rect.h)
        .background(tile.color)
        .border_brush(ring)
        .border_thickness(if focus == Focus::Chosen { 2.0 } else { 0.0 })
        .opacity(if focus == Focus::Outside { 0.3 } else { 1.0 })
        .corner_radius(2.0)
        .padding(Thickness::new(4.0, 2.0, 4.0, 2.0))
        .is_tab_stop(false)
        .automation_name(format!("{}: {}", tile.name, tile.detail));
    if let Of::File(path) = &tile.of {
        let path = path.clone();
        border = border.on_pointer_pressed(context.callback(move |_: PointerEventInfo| {
            Msg::Dash(Dash::Select(path.clone(), Origin::Map))
        }));
    }
    let (named, counted_too) = label_room(&tile.rect);
    if named {
        border = border.content(label(tile, counted_too));
    }
    border.tooltip(&tile.tip)
}

/// The map: the tiles on a canvas of `canvas` units that scales to the room it is given.
pub(super) fn map(
    placed: &[Placed],
    canvas: (f64, f64),
    selected: Option<&Path>,
    folder_selected: bool,
    context: Context<'_>,
) -> Border {
    let tiles: Vec<View> = placed
        .iter()
        .map(|tile| tile_view(tile, focus(&tile.of, selected, folder_selected), context))
        .collect();
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .padding(6.0)
        .content(
            Viewbox::new()
                .stretch(Stretch::Uniform)
                .horizontal_alignment(HorizontalAlignment::Center)
                .vertical_alignment(VerticalAlignment::Center)
                .content(
                    Canvas::new()
                        .width(canvas.0)
                        .height(canvas.1)
                        .children(tiles),
                ),
        )
}

#[cfg(test)]
mod tests {
    use piikey::inventory::{Rest, Tile, Tiles};

    use super::*;

    fn tile(path: &str, counts: &[(EntityKind, u32)]) -> Tile {
        Tile {
            path: PathBuf::from(path),
            size: 100,
            hits: counts.iter().map(|&(_, n)| u64::from(n)).sum(),
            counts: counts.to_vec(),
        }
    }

    fn tiles(list: Vec<Tile>) -> Tiles {
        Tiles {
            tiles: list,
            rest: Rest::default(),
        }
    }

    const AREA: Rect = Rect {
        x: 0.0,
        y: 0.0,
        w: 600.0,
        h: 400.0,
    };

    fn files() -> Tiles {
        tiles(vec![
            tile(r"C:\Docs\Taxes\2023.pdf", &[(EntityKind::Iban, 30)]),
            tile(r"C:\Docs\Taxes\2022.pdf", &[(EntityKind::Iban, 20)]),
            tile(
                r"C:\Docs\cv.docx",
                &[(EntityKind::Person, 8), (EntityKind::Email, 4)],
            ),
            tile(r"C:\Mail\jan.eml", &[(EntityKind::Email, 12)]),
        ])
    }

    #[test]
    fn every_file_gets_a_tile_inside_the_area_and_no_two_overlap() {
        let placed = place(&files(), Path::new(""), None, AREA);
        assert_eq!(placed.len(), 4);
        for (i, a) in placed.iter().enumerate() {
            let r = a.rect;
            assert!(r.x >= 0.0 && r.y >= 0.0, "{} starts outside", a.name);
            assert!(r.x + r.w <= AREA.w + 1e-6 && r.y + r.h <= AREA.h + 1e-6);
            for b in &placed[i + 1..] {
                let q = b.rect;
                let apart = r.x + r.w <= q.x + 1e-6
                    || q.x + q.w <= r.x + 1e-6
                    || r.y + r.h <= q.y + 1e-6
                    || q.y + q.h <= r.y + 1e-6;
                assert!(apart, "{} and {} overlap", a.name, b.name);
            }
        }
    }

    #[test]
    fn a_tile_is_as_big_as_what_the_file_holds() {
        let placed = place(&files(), Path::new(""), None, AREA);
        let area = |name: &str| {
            placed
                .iter()
                .find(|tile| tile.name == name)
                .map(|tile| tile.rect.w * tile.rect.h)
        };
        let (big, small) = (area("2023.pdf"), area("2022.pdf"));
        assert!(big > small, "{big:?} should beat {small:?}");
    }

    #[test]
    fn a_tile_has_the_colour_of_the_type_its_file_holds_most_of() {
        let placed = place(&files(), Path::new(""), None, AREA);
        let color = |name: &str| {
            placed
                .iter()
                .find(|tile| tile.name == name)
                .map(|t| t.color)
        };
        assert_eq!(color("2023.pdf"), Some(kind_color(EntityKind::Iban)));
        assert_eq!(color("cv.docx"), Some(kind_color(EntityKind::Person)));
        assert_eq!(color("jan.eml"), Some(kind_color(EntityKind::Email)));
    }

    #[test]
    fn the_files_of_a_folder_lie_together() {
        let placed = place(&files(), Path::new(""), None, AREA);
        let rect = |name: &str| placed.iter().find(|t| t.name == name).map(|t| t.rect);
        let (a, b) = (rect("2023.pdf"), rect("2022.pdf"));
        let (Some(a), Some(b)) = (a, b) else {
            panic!("the Taxes files have tiles");
        };
        // The two tax files are the whole of Taxes: their union is a rectangle, and no other tile
        // lies inside it.
        let (left, top) = (a.x.min(b.x), a.y.min(b.y));
        let (right, bottom) = ((a.x + a.w).max(b.x + b.w), (a.y + a.h).max(b.y + b.h));
        for other in placed
            .iter()
            .filter(|t| t.name != "2023.pdf" && t.name != "2022.pdf")
        {
            let r = other.rect;
            let inside = r.x >= left - 1e-6
                && r.y >= top - 1e-6
                && r.x + r.w <= right + 1e-6
                && r.y + r.h <= bottom + 1e-6;
            assert!(!inside, "{} lies in the Taxes folder's room", other.name);
        }
    }

    #[test]
    fn a_type_filter_keeps_the_files_that_hold_it_sized_by_how_much() {
        let placed = place(&files(), Path::new(""), Some(EntityKind::Email), AREA);
        let names: Vec<&str> = placed.iter().map(|tile| tile.name.as_str()).collect();
        assert_eq!(placed.len(), 2, "{names:?}");
        assert!(names.contains(&"cv.docx") && names.contains(&"jan.eml"));
        for tile in &placed {
            assert_eq!(tile.color, kind_color(EntityKind::Email));
        }
        let area = |name: &str| {
            placed
                .iter()
                .find(|tile| tile.name == name)
                .map(|tile| tile.rect.w * tile.rect.h)
        };
        // 12 emails against 4.
        assert!(area("jan.eml") > area("cv.docx"));
    }

    #[test]
    fn the_files_beyond_the_tiles_are_one_grey_tile() {
        let mut shown = files();
        shown.rest = Rest {
            files: 7,
            hits: 14,
            counts: vec![(EntityKind::Email, 14)],
        };
        let placed = place(&shown, Path::new(""), None, AREA);
        let rest: Vec<&Placed> = placed.iter().filter(|t| t.of == Of::Rest).collect();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].name, "+7 files");
        assert_eq!(rest[0].color, NEUTRAL);
        assert_eq!(rest[0].detail, "14 found");
        // Of another type, it is not there.
        let none = place(&shown, Path::new(""), Some(EntityKind::Iban), AREA);
        assert!(none.iter().all(|t| t.of != Of::Rest));
    }

    #[test]
    fn nothing_to_show_gives_no_tiles() {
        assert!(place(&tiles(Vec::new()), Path::new(""), None, AREA).is_empty());
        let empty = Rect { w: 0.0, ..AREA };
        assert!(place(&files(), Path::new(""), None, empty).is_empty());
    }

    #[test]
    fn a_path_is_laid_out_below_the_folder_on_show() {
        let at = Path::new(r"C:\Docs");
        let only = tiles(vec![
            tile(r"C:\Docs\Taxes\2023.pdf", &[(EntityKind::Iban, 30)]),
            tile(r"C:\Docs\cv.docx", &[(EntityKind::Person, 8)]),
        ]);
        assert_eq!(place(&only, at, None, AREA).len(), 2);
        assert_eq!(way(Path::new(r"C:\Docs\Taxes\2023.pdf"), at), ["taxes"]);
        assert!(way(Path::new(r"C:\Docs\cv.docx"), at).is_empty());
    }

    #[test]
    fn the_files_of_a_drive_lie_together_and_so_do_two_spellings_of_a_folder() {
        let on_two = tiles(vec![
            tile(r"C:\Docs\a.pdf", &[(EntityKind::Email, 30)]),
            tile(r"c:\DOCS\b.pdf", &[(EntityKind::Email, 20)]),
            tile(r"D:\Backup\c.pdf", &[(EntityKind::Email, 25)]),
            tile(r"D:\Other\d.pdf", &[(EntityKind::Email, 5)]),
        ]);
        let placed = place(&on_two, Path::new(""), None, AREA);
        assert_eq!(placed.len(), 4);
        let rect = |name: &str| placed.iter().find(|t| t.name == name).map(|t| t.rect);
        let (Some(a), Some(b)) = (rect("a.pdf"), rect("b.pdf")) else {
            panic!("the Docs files have tiles");
        };
        // Both spellings are one folder, so the two files are all of it: their union holds no
        // other tile, not even one of the other drive.
        let (left, top) = (a.x.min(b.x), a.y.min(b.y));
        let (right, bottom) = ((a.x + a.w).max(b.x + b.w), (a.y + a.h).max(b.y + b.h));
        for other in placed
            .iter()
            .filter(|t| t.name != "a.pdf" && t.name != "b.pdf")
        {
            let r = other.rect;
            let inside = r.x >= left - 1e-6
                && r.y >= top - 1e-6
                && r.x + r.w <= right + 1e-6
                && r.y + r.h <= bottom + 1e-6;
            assert!(
                !inside,
                "{} lies in the room of the Docs folder",
                other.name
            );
        }
    }

    #[test]
    fn a_selected_folder_picks_out_its_files() {
        let docs = Path::new(r"C:\Docs");
        let inside = Of::File(PathBuf::from(r"c:\docs\Taxes\2023.pdf"));
        let outside = Of::File(PathBuf::from(r"C:\Mail\jan.eml"));
        assert_eq!(focus(&inside, Some(docs), true), Focus::Inside);
        assert_eq!(focus(&outside, Some(docs), true), Focus::Outside);
        assert_eq!(focus(&Of::Rest, Some(docs), true), Focus::Outside);
        // A selected file is the one tile; the others stay as they are.
        let file = Path::new(r"C:\Mail\jan.eml");
        assert_eq!(focus(&outside, Some(file), false), Focus::Chosen);
        assert_eq!(focus(&inside, Some(file), false), Focus::None);
        assert_eq!(focus(&inside, None, false), Focus::None);
    }

    #[test]
    fn a_label_needs_room() {
        let rect = |w: f64, h: f64| Rect {
            x: 0.0,
            y: 0.0,
            w,
            h,
        };
        assert_eq!(label_room(&rect(200.0, 100.0)), (true, true));
        assert_eq!(label_room(&rect(200.0, 30.0)), (true, false));
        assert_eq!(label_room(&rect(40.0, 100.0)), (false, false));
        assert_eq!(label_room(&rect(200.0, 10.0)), (false, false));
    }
}
