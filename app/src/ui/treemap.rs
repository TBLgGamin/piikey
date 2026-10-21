//! Squarified treemap layout (Bruls, Huizing, van Wijk): tiles whose areas follow the weights and
//! whose aspect ratios stay close to 1, so every tile is big enough to click and label.

/// A rectangle in the layout's own units (the inventory card uses a 1000 × 420 canvas).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Rect {
    /// An empty rectangle at `(x, y)`: where tiles without weight go.
    const fn empty(x: f64, y: f64) -> Self {
        Self {
            x,
            y,
            w: 0.0,
            h: 0.0,
        }
    }
}

/// Lays `weights` out inside `area`, one rectangle per weight in the same order.
///
/// The caller sorts the weights descending; that gives the best aspect ratios but is not needed
/// for correctness. A weight that is zero, negative or not finite gets an empty rectangle at the
/// area's corner. When no weight counts, or `area` is empty or not finite, the result is empty.
#[must_use]
pub fn squarify(weights: &[f64], area: Rect) -> Vec<Rect> {
    let counts = |w: f64| w.is_finite() && w > 0.0;
    let total: f64 = weights.iter().copied().filter(|&w| counts(w)).sum();
    // A NaN or infinite side would otherwise lay out NaN tiles: `NaN <= 0.0` is false.
    if !(counts(total) && counts(area.w) && counts(area.h)) {
        return Vec::new();
    }
    let scale = area.w * area.h / total;
    let mut out = vec![Rect::empty(area.x, area.y); weights.len()];
    // (index into `weights`, area the tile will take)
    let items: Vec<(usize, f64)> = weights
        .iter()
        .enumerate()
        .filter(|&(_, &w)| counts(w))
        .map(|(i, &w)| (i, w * scale))
        .collect();

    let mut free = area;
    let mut start = 0;
    while start < items.len() && free.w > 0.0 && free.h > 0.0 {
        let side = free.w.min(free.h);
        let mut end = start + 1;
        let (mut sum, mut big, mut small) = (items[start].1, items[start].1, items[start].1);
        let mut worst = worst_ratio(sum, big, small, side);
        while let Some(&(_, next)) = items.get(end) {
            let (grown, bigger, smaller) = (sum + next, big.max(next), small.min(next));
            let ratio = worst_ratio(grown, bigger, smaller, side);
            if ratio > worst {
                break;
            }
            (sum, big, small, worst, end) = (grown, bigger, smaller, ratio, end + 1);
        }
        let row = &items[start..end];
        if free.w >= free.h {
            // A column on the left edge, its tiles stacked top to bottom.
            let width = sum / free.h;
            let mut y = free.y;
            for &(i, a) in row {
                let h = a / width;
                out[i] = Rect {
                    x: free.x,
                    y,
                    w: width,
                    h,
                };
                y += h;
            }
            free.x += width;
            free.w -= width;
        } else {
            // A row along the top edge, its tiles side by side.
            let height = sum / free.w;
            let mut x = free.x;
            for &(i, a) in row {
                let w = a / height;
                out[i] = Rect {
                    x,
                    y: free.y,
                    w,
                    h: height,
                };
                x += w;
            }
            free.y += height;
            free.h -= height;
        }
        start = end;
    }
    out
}

/// The worst aspect ratio in a row of total area `sum` laid along a side of length `side`, with
/// the biggest and smallest tile areas `big` and `small`.
fn worst_ratio(sum: f64, big: f64, small: f64, side: f64) -> f64 {
    let (sum_sq, side_sq) = (sum * sum, side * side);
    (side_sq * big / sum_sq).max(sum_sq / (side_sq * small))
}

#[cfg(test)]
mod tests {
    use super::{Rect, squarify};

    const AREA: Rect = Rect {
        x: 10.0,
        y: 20.0,
        w: 1000.0,
        h: 420.0,
    };
    const WEIGHTS: [f64; 9] = [60.0, 41.0, 30.0, 22.0, 15.0, 9.0, 5.0, 3.0, 1.0];

    fn overlap(a: &Rect, b: &Rect) -> f64 {
        let w = (a.x + a.w).min(b.x + b.w) - a.x.max(b.x);
        let h = (a.y + a.h).min(b.y + b.h) - a.y.max(b.y);
        if w > 0.0 && h > 0.0 { w * h } else { 0.0 }
    }

    #[test]
    fn areas_follow_weights() {
        let tiles = squarify(&WEIGHTS, AREA);
        assert_eq!(tiles.len(), WEIGHTS.len());
        let total: f64 = WEIGHTS.iter().sum();
        for (tile, weight) in tiles.iter().zip(WEIGHTS) {
            let want = AREA.w * AREA.h * weight / total;
            assert!(
                (tile.w * tile.h - want).abs() < 1e-6,
                "{tile:?} should cover {want}"
            );
        }
    }

    #[test]
    fn tiles_do_not_overlap() {
        let tiles = squarify(&WEIGHTS, AREA);
        for (i, a) in tiles.iter().enumerate() {
            for b in &tiles[i + 1..] {
                assert!(overlap(a, b) < 1e-6, "{a:?} overlaps {b:?}");
            }
        }
    }

    #[test]
    fn tiles_cover_the_area() {
        let tiles = squarify(&WEIGHTS, AREA);
        let covered: f64 = tiles.iter().map(|t| t.w * t.h).sum();
        assert!((covered - AREA.w * AREA.h).abs() < 1e-6);
        for t in &tiles {
            assert!(
                t.x >= AREA.x - 1e-9 && t.y >= AREA.y - 1e-9,
                "{t:?} starts outside"
            );
            assert!(
                t.x + t.w <= AREA.x + AREA.w + 1e-9,
                "{t:?} ends right of the area"
            );
            assert!(
                t.y + t.h <= AREA.y + AREA.h + 1e-9,
                "{t:?} ends below the area"
            );
        }
    }

    #[test]
    fn a_single_weight_fills_the_area() {
        let tiles = squarify(&[7.0], AREA);
        assert_eq!(tiles.len(), 1);
        let t = tiles[0];
        for (got, want) in [(t.x, AREA.x), (t.y, AREA.y), (t.w, AREA.w), (t.h, AREA.h)] {
            assert!((got - want).abs() < 1e-9, "{t:?} should equal {AREA:?}");
        }
    }

    #[test]
    fn nothing_to_lay_out_gives_nothing() {
        assert!(squarify(&[], AREA).is_empty());
        assert!(squarify(&[0.0, 0.0], AREA).is_empty());
    }

    #[test]
    fn an_area_that_is_not_finite_gives_nothing() {
        for (w, h) in [(f64::NAN, 420.0), (1000.0, f64::INFINITY), (-1.0, 420.0)] {
            let area = Rect { w, h, ..AREA };
            assert!(squarify(&WEIGHTS, area).is_empty(), "{area:?}");
        }
        // Weights whose sum overflows have no scale.
        assert!(squarify(&[f64::MAX, f64::MAX], AREA).is_empty());
    }

    #[test]
    fn weightless_tiles_are_empty() {
        let tiles = squarify(&[3.0, 0.0, 1.0], AREA);
        assert_eq!(tiles.len(), 3);
        assert!(tiles[1].w == 0.0 && tiles[1].h == 0.0);
        let covered: f64 = tiles.iter().map(|t| t.w * t.h).sum();
        assert!((covered - AREA.w * AREA.h).abs() < 1e-6);
    }
}
