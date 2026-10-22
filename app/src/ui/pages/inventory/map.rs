//! The layout of the treemap: which tiles there are, where they lie on the canvas and how they
//! look. No widgets; the card in [`super`] draws what this decides.

use std::path::PathBuf;

use piikey::inventory::Node;
use windows_reactor::Color;

use super::panel::{more_title, totals};
use crate::ui::{
    pages::kit::{counted, thousands},
    treemap::{Rect, squarify},
    window::Selection,
};

/// Width and height of the treemap's canvas in its own units; the viewbox scales it to the card.
pub(super) const MAP_W: f64 = 1000.0;
pub(super) const MAP_H: f64 = 420.0;
/// Tiles that get a place of their own; the nodes after them share one "+N more" tile.
pub(super) const MAX_TILES: usize = 60;
/// How far a tile keeps clear of its neighbours on each side.
const TILE_INSET: f64 = 2.0;
/// The plan's floor for a tile that carries its name and counts: this wide and this high, on the
/// canvas. [`shows_label`] asks for the room the two lines take as well, which is more.
const LABEL_MIN: (f64, f64) = (90.0, 40.0);
/// The font size of a tile's name grows with the tile, between these limits. The viewbox shrinks
/// the canvas to the card, mostly to between a third and two thirds, so the text is set big.
const NAME_SIZES: (f64, f64) = (22.0, 28.0);
/// The height of a line of text, in font sizes.
const LINE: f64 = 1.35;
/// What a button keeps clear of its text, above and below together.
const TILE_PADDING: f64 = 10.0;

/// The tile colour for the fewest values, in the light theme: a pale lilac.
const LIGHT_FEWEST: Color = Color::rgb(0xe6, 0xde, 0xf6);
/// The tile colour for the most values, in the light theme: the brand purple.
const LIGHT_MOST: Color = Color::rgb(0x6f, 0x49, 0xb1);
/// The tile colour for the fewest values, in the dark theme: a deep purple.
const DARK_FEWEST: Color = Color::rgb(0x3b, 0x2f, 0x63);
/// The tile colour for the most values, in the dark theme: the brand lilac.
const DARK_MOST: Color = Color::rgb(0xd6, 0xc9, 0xf9);
/// The colour of the "+N more" tile and of a tile with no values: a grey in both themes.
const NEUTRAL: Color = Color::rgb(0x6e, 0x6e, 0x6e);
const WHITE: Color = Color::rgb(0xff, 0xff, 0xff);
const BLACK: Color = Color::rgb(0x00, 0x00, 0x00);
/// How far the colour of a hovered tile moves away from its label colour.
const HOVER_SHIFT: u16 = 10;
/// How far the colour of a pressed tile moves away from its label colour.
const PRESSED_SHIFT: u16 = 20;
/// What a label needs against its tile: WCAG AA for text.
#[cfg(test)]
const MIN_CONTRAST: f64 = 4.5;
/// Where a tile is before the layout has placed it.
const NO_RECT: Rect = Rect {
    x: 0.0,
    y: 0.0,
    w: 0.0,
    h: 0.0,
};

/// What a treemap tile stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TileOf {
    /// The node with this path (empty for "Other scans").
    Node(PathBuf),
    /// The nodes after the first [`MAX_TILES`], as one tile.
    More,
}

/// One tile of the treemap: where it lies on the canvas and what it says.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Tile {
    pub(super) of: TileOf,
    pub(super) rect: Rect,
    pub(super) color: Color,
    /// The colour of the name and counts: white or black, whichever reads better on `color`.
    pub(super) text: Color,
    /// The name, or "+N more".
    pub(super) title: String,
    /// "12 in 3 files".
    pub(super) detail: String,
}

/// A node's share of the treemap: the values found under it.
#[expect(
    clippy::cast_precision_loss,
    reason = "a tile's area needs no precision beyond 2^53 values"
)]
fn weight(hits: u64) -> f64 {
    hits as f64
}

/// `12 in 3 files`: what a tile says under its name.
fn tile_detail(hits: u64, files: u64) -> String {
    format!("{} in {}", thousands(hits), counted(files, "file", "files"))
}

/// The ramp's colour for a tile of `percent` (0 to 100) of the largest: the fewest values are the
/// lightest in the light theme; in the dark theme the most values are the brightest.
pub(super) fn ramp(percent: u16, dark: bool) -> Color {
    if dark {
        blend(DARK_FEWEST, DARK_MOST, percent)
    } else {
        blend(LIGHT_FEWEST, LIGHT_MOST, percent)
    }
}

/// How much of the largest tile's `max` values `hits` are, in whole percent.
fn share(hits: u64, max: u64) -> u16 {
    if max == 0 {
        return 0;
    }
    let percent = u128::from(hits.min(max)) * 100 / u128::from(max);
    u16::try_from(percent).unwrap_or(100)
}

/// The brightness of `color` as WCAG defines it, from 0 (black) to 1 (white).
pub(super) fn relative_luminance(color: Color) -> f64 {
    let linear = |value: u8| {
        let c = f64::from(value) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
}

/// The WCAG contrast ratio of two colours, from 1 to 21.
pub(super) fn contrast_ratio(a: Color, b: Color) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The label colour for `color`: pure white or pure black, whichever has the higher contrast. The
/// better of the two is never below 4.58:1.
pub(super) fn text_on(color: Color) -> Color {
    if contrast_ratio(color, WHITE) >= contrast_ratio(color, BLACK) {
        WHITE
    } else {
        BLACK
    }
}

/// `color` moved `percent` away from its label colour `text`: the hover and pressed colours of a
/// tile, which can only gain contrast with the label.
pub(super) fn shifted(color: Color, text: Color, percent: u16) -> Color {
    let away = if text == WHITE { BLACK } else { WHITE };
    blend(color, away, percent)
}

/// The colour of a tile under the pointer.
pub(super) fn hover_color(tile: &Tile) -> Color {
    shifted(tile.color, tile.text, HOVER_SHIFT)
}

/// The colour of a tile being pressed.
pub(super) fn pressed_color(tile: &Tile) -> Color {
    shifted(tile.color, tile.text, PRESSED_SHIFT)
}

/// `from`, `percent` of the way to `to`.
pub(super) fn blend(from: Color, to: Color, percent: u16) -> Color {
    let percent = percent.min(100);
    let mix = |a: u8, b: u8| {
        let value = (u16::from(a) * (100 - percent) + u16::from(b) * percent) / 100;
        u8::try_from(value).unwrap_or(u8::MAX)
    };
    Color::rgb(mix(from.r, to.r), mix(from.g, to.g), mix(from.b, to.b))
}

/// `rect` pulled in by [`TILE_INSET`] on every side; less for a tile too small to spare it.
fn inset(rect: Rect) -> Rect {
    let by = TILE_INSET.min(rect.w / 4.0).min(rect.h / 4.0);
    Rect {
        x: rect.x + by,
        y: rect.y + by,
        w: rect.w - 2.0 * by,
        h: rect.h - 2.0 * by,
    }
}

/// The font sizes of a tile's name and its counts: they grow with the tile, within limits.
pub(super) fn label_sizes(rect: &Rect) -> (f64, f64) {
    let name = (rect.w.min(rect.h) / 5.0).clamp(NAME_SIZES.0, NAME_SIZES.1);
    (name, name * 0.8)
}

/// Whether a tile has room for its name and counts: the plan's [`LABEL_MIN`], and the height of
/// the two lines at the sizes [`label_sizes`] picks.
pub(super) fn shows_label(rect: &Rect) -> bool {
    let (name, counts) = label_sizes(rect);
    let lines = (name + counts) * LINE + TILE_PADDING;
    rect.w >= LABEL_MIN.0 && rect.h >= LABEL_MIN.1 && rect.h >= lines
}

/// The tile of `node`, coloured by its share of `max`, with its weight in the layout.
fn node_tile(node: &Node, max: u64, dark: bool) -> (f64, Tile) {
    let color = if node.hits == 0 {
        NEUTRAL
    } else {
        ramp(share(node.hits, max), dark)
    };
    let tile = Tile {
        of: TileOf::Node(node.path.clone()),
        rect: NO_RECT,
        color,
        text: text_on(color),
        title: node.name.clone(),
        detail: tile_detail(node.hits, u64::from(node.files)),
    };
    (weight(node.hits), tile)
}

/// The tile for the nodes that did not get one of their own, with its weight in the layout.
fn more_tile(rest: &[Node]) -> (f64, Tile) {
    let (hits, files) = totals(rest);
    let tile = Tile {
        of: TileOf::More,
        rect: NO_RECT,
        color: NEUTRAL,
        text: text_on(NEUTRAL),
        title: more_title(rest.len()),
        detail: tile_detail(hits, files),
    };
    (weight(hits), tile)
}

/// The treemap of `nodes`, the one with most values first: a tile for each of the first
/// [`MAX_TILES`] and one for all the others, sized by the values found and laid out on the canvas.
/// The tiles are coloured by their values against the largest of them, for the `dark` theme or not.
pub(super) fn tiles(nodes: &[Node], dark: bool) -> Vec<Tile> {
    let (head, others) = nodes.split_at(nodes.len().min(MAX_TILES));
    let max = head.iter().map(|node| node.hits).max().unwrap_or(0);
    let mut items: Vec<(f64, Tile)> = head.iter().map(|node| node_tile(node, max, dark)).collect();
    if !others.is_empty() {
        items.push(more_tile(others));
    }
    // The biggest first makes the squarest tiles; tiles of equal weight keep their order.
    items.sort_by(|a, b| b.0.total_cmp(&a.0));
    let weights: Vec<f64> = items.iter().map(|(w, _)| *w).collect();
    let area = Rect {
        x: 0.0,
        y: 0.0,
        w: MAP_W,
        h: MAP_H,
    };
    items
        .into_iter()
        .zip(squarify(&weights, area))
        .filter_map(|((_, tile), rect)| {
            let rect = inset(rect);
            (rect.w > 0.0 && rect.h > 0.0).then_some(Tile { rect, ..tile })
        })
        .collect()
}

/// Whether the side panel shows the tile standing for `of`.
pub(super) fn is_selected(of: &TileOf, selected: Option<&Selection>) -> bool {
    match (of, selected) {
        (TileOf::Node(path), Some(Selection::Node(chosen))) => path == chosen,
        (TileOf::More, Some(Selection::More)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use piikey::detect::EntityKind;

    use crate::ui::pages::inventory::fixtures::{node, nodes};

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn only_the_first_sixty_nodes_get_a_tile_and_the_rest_share_one() {
        let nodes = nodes(100);
        let tiles = tiles(&nodes, false);
        assert_eq!(tiles.len(), MAX_TILES + 1);
        let own: Vec<&PathBuf> = tiles
            .iter()
            .filter_map(|tile| match &tile.of {
                TileOf::Node(path) => Some(path),
                TileOf::More => None,
            })
            .collect();
        assert_eq!(own.len(), MAX_TILES);
        for node in &nodes[..MAX_TILES] {
            assert!(own.contains(&&node.path), "{} has no tile", node.name);
        }
        let more: Vec<&Tile> = tiles
            .iter()
            .filter(|tile| tile.of == TileOf::More)
            .collect();
        assert_eq!(more.len(), 1);
        assert_eq!(more[0].title, "+40 more");
        let rest_hits: u64 = nodes[MAX_TILES..].iter().map(|node| node.hits).sum();
        assert_eq!(more[0].detail, tile_detail(rest_hits, 40));
        assert_eq!(more[0].color, NEUTRAL);
    }

    #[test]
    fn few_nodes_need_no_more_tile() {
        let tiles = tiles(&nodes(MAX_TILES), false);
        assert_eq!(tiles.len(), MAX_TILES);
        assert!(tiles.iter().all(|tile| tile.of != TileOf::More));
        assert!(super::tiles(&[], false).is_empty());
    }

    #[test]
    fn the_more_tile_is_placed_by_its_weight_among_the_others() {
        // Sixty tiles of one value, and forty more of one: together the biggest tile of all.
        let nodes: Vec<Node> = (0..100)
            .map(|i| node(&format!("n{i}"), 1, EntityKind::Email))
            .collect();
        let tiles = tiles(&nodes, false);
        assert_eq!(tiles[0].of, TileOf::More);
        assert!(tiles[0].rect.w * tiles[0].rect.h > tiles[1].rect.w * tiles[1].rect.h);
    }

    #[test]
    fn a_lone_tile_fills_the_canvas_less_the_inset() {
        let tiles = tiles(&nodes(1), false);
        assert_eq!(tiles.len(), 1);
        let rect = tiles[0].rect;
        assert!(near(rect.x, TILE_INSET) && near(rect.y, TILE_INSET));
        assert!(near(rect.w, MAP_W - 2.0 * TILE_INSET));
        assert!(near(rect.h, MAP_H - 2.0 * TILE_INSET));
    }

    #[test]
    fn tiles_stay_on_the_canvas_and_apart() {
        let tiles = tiles(&nodes(100), false);
        for (i, a) in tiles.iter().enumerate() {
            let ra = a.rect;
            assert!(
                ra.x >= 0.0 && ra.y >= 0.0,
                "{} starts off the canvas",
                a.title
            );
            assert!(ra.x + ra.w <= MAP_W + 1e-6 && ra.y + ra.h <= MAP_H + 1e-6);
            for b in &tiles[i + 1..] {
                let rb = b.rect;
                let apart = ra.x + ra.w <= rb.x
                    || rb.x + rb.w <= ra.x
                    || ra.y + ra.h <= rb.y
                    || rb.y + rb.h <= ra.y;
                assert!(apart, "{} and {} overlap", a.title, b.title);
            }
        }
    }

    #[test]
    fn a_tile_too_small_to_spare_the_inset_keeps_some_size() {
        let small = inset(Rect {
            x: 10.0,
            y: 10.0,
            w: 6.0,
            h: 100.0,
        });
        assert!(small.w > 0.0 && near(small.w, 3.0));
        assert!(near(small.x, 11.5));
        let none = inset(Rect {
            x: 10.0,
            y: 10.0,
            w: 0.0,
            h: 0.0,
        });
        assert!(near(none.w, 0.0) && near(none.h, 0.0));
    }

    #[test]
    fn text_needs_ninety_by_forty_and_room_for_its_two_lines() {
        let rect = |w: f64, h: f64| Rect {
            x: 0.0,
            y: 0.0,
            w,
            h,
        };
        assert!(shows_label(&rect(400.0, 300.0)));
        assert!(shows_label(&rect(90.0, 70.0)));
        // Below the plan's floor, in either direction.
        assert!(!shows_label(&rect(89.9, 300.0)));
        assert!(!shows_label(&rect(30.0, 300.0)));
        assert!(!shows_label(&rect(300.0, 39.9)));
        // Over the floor, but not high enough for two lines at the smallest size.
        assert!(!shows_label(&rect(90.0, 40.0)));
        assert!(!shows_label(&rect(300.0, 60.0)));
    }

    #[test]
    fn label_sizes_grow_with_the_tile_within_limits() {
        let size = |w: f64, h: f64| {
            label_sizes(&Rect {
                x: 0.0,
                y: 0.0,
                w,
                h,
            })
        };
        let (small, small_counts) = size(90.0, 70.0);
        assert!(near(small, NAME_SIZES.0) && small_counts < small);
        let (mid, _) = size(200.0, 125.0);
        assert!(near(mid, 25.0));
        let (big, _) = size(900.0, 400.0);
        assert!(near(big, NAME_SIZES.1));
    }

    /// Every step of the ramp, in both themes, paired with the theme.
    fn whole_ramp() -> impl Iterator<Item = (u16, bool, Color)> {
        [false, true]
            .into_iter()
            .flat_map(|dark| (0..=100).map(move |percent| (percent, dark, ramp(percent, dark))))
    }

    fn tile_of(color: Color) -> Tile {
        Tile {
            of: TileOf::More,
            rect: NO_RECT,
            color,
            text: text_on(color),
            title: String::new(),
            detail: String::new(),
        }
    }

    #[test]
    fn the_label_reads_on_every_step_of_the_ramp_in_both_themes() {
        for (percent, dark, color) in whole_ramp() {
            let ratio = contrast_ratio(color, text_on(color));
            assert!(ratio >= MIN_CONTRAST, "{percent}% dark={dark}: {ratio:.2}");
        }
        let ratio = contrast_ratio(NEUTRAL, text_on(NEUTRAL));
        assert!(ratio >= MIN_CONTRAST, "neutral: {ratio:.2}");
    }

    #[test]
    fn hovering_and_pressing_keep_the_label_readable() {
        for (percent, dark, color) in whole_ramp().chain([(0, false, NEUTRAL)]) {
            let tile = tile_of(color);
            for (state, shade) in [
                ("hover", hover_color(&tile)),
                ("pressed", pressed_color(&tile)),
            ] {
                let ratio = contrast_ratio(shade, tile.text);
                assert!(
                    ratio >= MIN_CONTRAST,
                    "{state} at {percent}% dark={dark}: {ratio:.2}"
                );
            }
        }
    }

    #[test]
    fn more_values_are_darker_in_the_light_theme_and_brighter_in_the_dark_one() {
        let light: Vec<f64> = (0..=100)
            .map(|p| relative_luminance(ramp(p, false)))
            .collect();
        assert!(light.windows(2).all(|pair| pair[1] <= pair[0]));
        assert!(light[100] < light[0]);
        let dark: Vec<f64> = (0..=100)
            .map(|p| relative_luminance(ramp(p, true)))
            .collect();
        assert!(dark.windows(2).all(|pair| pair[1] >= pair[0]));
        assert!(dark[100] > dark[0]);
    }

    #[test]
    fn the_ramp_ends_in_the_brand_colours() {
        assert_eq!(ramp(100, false), Color::rgb(0x6f, 0x49, 0xb1));
        assert_eq!(ramp(100, true), Color::rgb(0xd6, 0xc9, 0xf9));
    }

    #[test]
    fn a_tile_is_coloured_by_its_values_against_the_largest() {
        let nodes = vec![
            node("big", 100, EntityKind::Email),
            node("half", 50, EntityKind::Email),
        ];
        let tiles = tiles(&nodes, false);
        let color_of = |name: &str| {
            tiles
                .iter()
                .find(|tile| tile.title == name)
                .map(|tile| tile.color)
        };
        assert_eq!(color_of("big"), Some(ramp(100, false)));
        assert_eq!(color_of("half"), Some(ramp(50, false)));
    }

    #[test]
    fn the_label_is_pure_white_or_black_whichever_reads_better() {
        assert_eq!(text_on(Color::rgb(0x20, 0x20, 0x20)), WHITE);
        assert_eq!(text_on(Color::rgb(0xf0, 0xf0, 0xf0)), BLACK);
        assert!((contrast_ratio(BLACK, WHITE) - 21.0).abs() < 1e-9);
    }

    #[test]
    fn blending_moves_each_channel_towards_the_other_colour() {
        assert_eq!(blend(BLACK, WHITE, 0), BLACK);
        assert_eq!(blend(BLACK, WHITE, 100), WHITE);
        assert_eq!(blend(BLACK, WHITE, 50), Color::rgb(127, 127, 127));
        assert_eq!(blend(BLACK, WHITE, 250), WHITE);
    }

    #[test]
    fn the_selected_tile_is_the_one_the_panel_shows() {
        let file = TileOf::Node(PathBuf::from(r"C:\Data\a.txt"));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\a.txt"));
        let other = Selection::Node(PathBuf::from(r"C:\Data\b.txt"));
        assert!(is_selected(&file, Some(&chosen)));
        assert!(!is_selected(&file, Some(&other)));
        assert!(!is_selected(&file, Some(&Selection::More)));
        assert!(!is_selected(&file, None));
        assert!(is_selected(&TileOf::More, Some(&Selection::More)));
        assert!(!is_selected(&TileOf::More, Some(&chosen)));
    }
}
