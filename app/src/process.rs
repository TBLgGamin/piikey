//! The programs running on this PC, by name.

use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System};

/// The file name of the program running as process `pid`, in lowercase (`chrome.exe`); `None` when
/// there is no such process or Windows gives it no name.
pub(crate) fn exe_name(pid: u32) -> Option<String> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    lowercase_name(system.process(pid)?)
}

/// The names of the programs running now: lowercase, unique, sorted.
pub(crate) fn running_names() -> Vec<String> {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut names: Vec<String> = system
        .processes()
        .values()
        .filter_map(lowercase_name)
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn lowercase_name(process: &Process) -> Option<String> {
    let name = process.name().to_string_lossy().to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::{exe_name, running_names};
    use crate::Describe;

    /// What this very test program is called, in lowercase.
    fn own_name() -> Result<String, String> {
        let exe = std::env::current_exe().describe()?;
        exe.file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .ok_or_else(|| "the test program has no file name".to_owned())
    }

    #[test]
    fn a_running_program_is_named_in_lowercase() -> Result<(), String> {
        let name = own_name()?;
        assert_eq!(exe_name(std::process::id()), Some(name.clone()));
        assert!(running_names().contains(&name));
        Ok(())
    }

    #[test]
    fn a_process_that_does_not_exist_has_no_name() {
        assert_eq!(exe_name(u32::MAX - 3), None);
    }

    #[test]
    fn the_running_names_are_sorted_unique_and_not_empty() {
        let names = running_names();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(names.iter().all(|name| !name.is_empty()));
    }
}
