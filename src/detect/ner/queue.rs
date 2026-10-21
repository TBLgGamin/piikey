//! The windows of a call that wait for the CPU and the GPU: what one run of each takes, what a
//! window costs, and the queue the two pull batches from at opposite ends.

use std::{ops::Range, sync::Mutex};

use super::lock;

/// What one run of the model takes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Windows.
    pub(super) rows: usize,
    /// Positions: the windows times the width of the longest, which every one is padded to.
    pub(super) positions: usize,
}

/// The CPU costs least per position at about a thousand positions a run and more beyond
/// (measured, for windows of 256 to 512 positions: 125 to 167 ms per 1000 positions at a
/// thousand, 200 to 235 at four thousand; short windows cost the same either way).
pub(super) const CPU_LIMITS: Limits = Limits {
    rows: 64,
    positions: 1024,
};

/// The GPU wants as many as it can get: a run costs it about 70 ms to start, 4.5 ms per window and
/// 0.07 ms per position (RTX 3070). The row limit keeps a run of short windows from taking seconds.
pub(super) const GPU_LIMITS: Limits = Limits {
    rows: 128,
    positions: 16384,
};

/// The least a run on the GPU is given, as what it would cost the CPU (see [`cost`]): below it the
/// run is mostly start-up. A call that would cost the CPU less than `GPU_SHARE` times this stays
/// on the CPU: about 85 short messages (measured: the GPU began to pay off between 80 and 100),
/// or three windows of 512 positions.
pub(super) const GPU_FLOOR: usize = 1600;

/// The GPU takes at most one in this many of what is left (by cost). It is the slower of the two
/// on short windows and the faster on long ones, and takes the long ones; half of what is left
/// keeps the CPU busy until the GPU's last run is done. (Measured on 600 short messages and on a
/// document of 40 windows: a third was 12 to 14% slower, and a quarter or a sixth slower still.)
pub(super) const GPU_SHARE: usize = 2;

/// What a window of `positions` positions costs the CPU, in positions of a short window. The
/// model reads every position and each one attends over the whole window, so a long window costs
/// more per position (measured on a Ryzen 5 9600X: 0.10 ms per position at 35 positions a window,
/// 0.23 at 512). The GPU is started for a call, and given its share of it, by what the call would
/// cost the CPU: two long windows are worth it, as are a hundred short ones.
fn cost(positions: usize) -> usize {
    positions + positions * positions / 380
}

/// The windows of a call that wait to be run, longest first. The GPU takes from the front (the
/// longest, which it runs best), the CPU from the back (the shortest). Each takes a batch at a
/// time, so the two meet in the middle, whatever their speeds.
pub(super) struct Queue<'a> {
    /// Tokens per window, longest first.
    lens: &'a [usize],
    /// `prefix[i]`: what the first `i` windows cost the CPU (see [`cost`]).
    prefix: Vec<usize>,
    /// The windows not taken yet.
    open: Mutex<Range<usize>>,
}

impl<'a> Queue<'a> {
    pub(super) fn new(lens: &'a [usize]) -> Self {
        let mut prefix = Vec::with_capacity(lens.len() + 1);
        let mut total = 0;
        prefix.push(total);
        for len in lens {
            // Plus `<bos>` and `<eos>`.
            total += cost(len + 2);
            prefix.push(total);
        }
        Self {
            lens,
            prefix,
            open: Mutex::new(0..lens.len()),
        }
    }

    /// What the windows not taken yet cost the CPU.
    pub(super) fn remaining(&self) -> usize {
        let open = lock(&self.open);
        self.cost_of(&open)
    }

    fn cost_of(&self, open: &Range<usize>) -> usize {
        self.prefix[open.end] - self.prefix[open.start]
    }

    pub(super) fn is_empty(&self) -> bool {
        lock(&self.open).is_empty()
    }

    /// The longest windows left, as many as fit `limits`, for the GPU. It is given at most one in
    /// `share` of what is left (by cost), so that the CPU, which gets the rest, finishes about
    /// when it does, and nothing under `floor`: a run that small is mostly start-up, and the CPU
    /// is quicker.
    pub(super) fn take_front(
        &self,
        limits: Limits,
        floor: usize,
        share: usize,
    ) -> Option<Range<usize>> {
        let mut open = lock(&self.open);
        if open.is_empty() {
            return None;
        }
        let budget = self.cost_of(&open) / share;
        if budget < floor {
            return None;
        }
        // The batch is padded to its longest window, the first.
        let width = self.lens[open.start] + 2;
        let each = cost(width);
        let mut rows = 1;
        while rows < limits.rows
            && open.start + rows < open.end
            && (rows + 1) * width <= limits.positions
            && (rows + 1) * each <= budget
        {
            rows += 1;
        }
        let batch = open.start..open.start + rows;
        open.start += rows;
        Some(batch)
    }

    /// The shortest windows left, as many as fit `limits`, for the CPU.
    pub(super) fn take_back(&self, limits: Limits) -> Option<Range<usize>> {
        let mut open = lock(&self.open);
        if open.is_empty() {
            return None;
        }
        // The batch is padded to its longest window, the first of it: the one before the batch
        // so far is what the next window would make the width.
        let mut rows = 1;
        while rows < limits.rows
            && open.end - rows > open.start
            && (rows + 1) * (self.lens[open.end - rows - 1] + 2) <= limits.positions
        {
            rows += 1;
        }
        open.end -= rows;
        Some(open.end..open.end + rows)
    }

    /// Puts back the windows from `from` on, which the GPU took and could not run. Only the GPU
    /// moves the front, and `from` is where its last batch began.
    pub(super) fn give_back(&self, from: usize) {
        let mut open = lock(&self.open);
        open.start = open.start.min(from);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn limits(rows: usize, positions: usize) -> Limits {
        Limits { rows, positions }
    }

    /// Window lengths from 1 to 510, longest first, from a seed.
    fn lens_of(count: usize, seed: u64) -> Vec<usize> {
        let mut state = seed;
        let mut lens: Vec<usize> = (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                usize::try_from((state >> 33) % 510).unwrap_or(0) + 1
            })
            .collect();
        lens.sort_unstable_by(|a, b| b.cmp(a));
        lens
    }

    #[test]
    fn the_cpu_takes_the_shortest_windows_padded_to_the_longest_of_the_batch() {
        let lens = [510, 510, 400, 300, 120, 50, 3, 1];
        let queue = Queue::new(&lens);
        let cpu = limits(64, 1024);
        // 1, 3, 50 and 120 tokens: 4 x 122 = 488 positions; the 300 would make it 5 x 302.
        assert_eq!(queue.take_back(cpu), Some(4..8));
        // 300 and 400: 2 x 402 = 804; a 510 would make it 3 x 512.
        assert_eq!(queue.take_back(cpu), Some(2..4));
        // Two windows of 512 positions are exactly 1024.
        assert_eq!(queue.take_back(cpu), Some(0..2));
        assert_eq!(queue.take_back(cpu), None);
        assert!(queue.is_empty());
        assert_eq!(queue.remaining(), 0);
    }

    #[test]
    fn the_row_limit_binds_for_short_windows_and_one_window_is_always_taken() {
        let lens = [10; 100];
        let queue = Queue::new(&lens);
        assert_eq!(queue.take_back(limits(16, 16384)), Some(84..100));
        // A window wider than the whole budget is still run, alone.
        let wide = [510, 510];
        let queue = Queue::new(&wide);
        assert_eq!(queue.take_back(limits(64, 100)), Some(1..2));
        assert_eq!(queue.take_back(limits(64, 100)), Some(0..1));
    }

    #[test]
    fn a_long_window_costs_the_cpu_more_per_position_than_a_short_one() {
        for width in 1..512 {
            assert!(cost(width + 1) > cost(width), "{width}");
        }
        let per_position = |width: usize| cost(width) * 1000 / width;
        assert!(per_position(512) > per_position(35));
    }

    #[test]
    fn the_gpu_takes_the_longest_windows_but_never_more_than_its_share() {
        let lens = [510; 10];
        let queue = Queue::new(&lens);
        let one = cost(512);
        assert_eq!(queue.remaining(), 10 * one);
        let gpu = limits(128, 16384);
        // Half of ten windows: five.
        assert_eq!(queue.take_front(gpu, one, 2), Some(0..5));
        // Half of five windows is two and a half: two.
        assert_eq!(queue.take_front(gpu, one, 2), Some(5..7));
        assert_eq!(queue.take_front(gpu, one, 2), Some(7..8));
        assert_eq!(queue.take_front(gpu, one, 2), Some(8..9));
        // Half of one window is under the floor: the last window is the CPU's.
        assert_eq!(queue.take_front(gpu, one, 2), None);
        assert_eq!(queue.remaining(), one);
        assert_eq!(queue.take_back(limits(64, 1024)), Some(9..10));
    }

    #[test]
    fn the_gpu_is_started_exactly_when_it_would_be_given_a_batch() {
        // The caller starts the GPU for a call that costs the CPU at least `GPU_FLOOR *
        // GPU_SHARE`: below that a GPU thread would find nothing to take, above it `take_front`
        // must have something.
        for width in [33, 120, 510] {
            let mut started = false;
            for count in 0..=600 {
                let lens = vec![width; count];
                let queue = Queue::new(&lens);
                let big_enough = queue.remaining() >= GPU_FLOOR * GPU_SHARE;
                let taken = queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE);
                assert_eq!(big_enough, taken.is_some(), "{count} windows of {width}");
                assert!(
                    big_enough || !started,
                    "a bigger call stays on the CPU alone: {count} windows of {width}"
                );
                started |= big_enough;
            }
        }
    }

    #[test]
    fn a_batch_the_gpu_could_not_run_goes_back_to_the_front() {
        let lens = [510; 12];
        let queue = Queue::new(&lens);
        let first = queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE);
        assert!(first.is_some());
        queue.give_back(0);
        assert_eq!(queue.remaining(), 12 * cost(512));
        assert_eq!(
            queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE),
            first,
            "the same windows again"
        );
    }

    #[test]
    fn a_batch_given_back_after_the_cpu_ran_dry_is_all_that_is_left() {
        let lens = [510; 12];
        let cpu = limits(64, 1024);
        let queue = Queue::new(&lens);
        let Some(failed) = queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE) else {
            panic!("the GPU is given a batch of 12 long windows");
        };
        // The CPU takes the rest and finds the queue empty before the GPU's run fails.
        let mut taken = vec![0u8; lens.len()];
        while let Some(batch) = queue.take_back(cpu) {
            for i in batch {
                taken[i] += 1;
            }
        }
        assert!(queue.is_empty());

        queue.give_back(failed.start);
        assert!(!queue.is_empty());
        while let Some(batch) = queue.take_back(cpu) {
            for i in batch {
                taken[i] += 1;
            }
        }
        assert!(taken.iter().all(|&times| times == 1), "{taken:?}");
        assert!(queue.is_empty());
    }

    #[test]
    fn both_ends_together_take_every_window_once_and_stay_within_their_limits() {
        let (gpu, cpu) = (limits(128, 16384), limits(64, 1024));
        for (seed, count) in [(1, 5), (2, 40), (3, 300), (4, 1000), (5, 4000)] {
            let lens = lens_of(count, seed);
            let queue = Queue::new(&lens);
            let mut times = vec![0u8; count];
            let mut state = seed;
            loop {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let (batch, allowed) = if (state >> 40) % 3 == 0 {
                    (queue.take_front(gpu, 64, 2), gpu)
                } else {
                    (None, cpu)
                };
                let (batch, allowed) = match batch {
                    Some(batch) => (batch, allowed),
                    None => match queue.take_back(cpu) {
                        Some(batch) => (batch, cpu),
                        None => break,
                    },
                };
                assert!(batch.len() <= allowed.rows);
                // Sorted longest first: the first window of a batch sets the width.
                assert!(
                    batch.len() == 1 || batch.len() * (lens[batch.start] + 2) <= allowed.positions
                );
                for i in batch {
                    times[i] += 1;
                }
            }
            assert!(times.iter().all(|&n| n == 1), "seed {seed}");
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn two_workers_pulling_from_both_ends_never_run_a_window_twice() {
        let lens = lens_of(30_000, 7);
        let queue = Queue::new(&lens);
        let seen: Vec<AtomicUsize> = lens.iter().map(|_| AtomicUsize::new(0)).collect();
        let note = |batch: Range<usize>| {
            for i in batch {
                seen[i].fetch_add(1, Ordering::SeqCst);
            }
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while let Some(batch) = queue.take_front(limits(128, 16384), 1024, 3) {
                    note(batch);
                }
            });
            while let Some(batch) = queue.take_back(limits(64, 1024)) {
                note(batch);
            }
        });
        assert!(queue.is_empty());
        assert!(seen.iter().all(|n| n.load(Ordering::SeqCst) == 1));
    }
}
