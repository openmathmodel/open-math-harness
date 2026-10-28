//! The shell service under the real kernel and sandbox: nothing a command
//! started outlives it, wherever it moved its process group or session,
//! when it returns and when its call is withdrawn because its caller ended
//! (as a person's Stop ends an agent).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nucleus_e2e::{Scenario, TIMEOUT, cap, ok_value, program, wait_for};
use serde_json::{Value, json};

/// How many host processes have `marker` as one of their arguments.
fn running(marker: &str) -> usize {
    let has_marker = |entry: &std::fs::DirEntry| {
        std::fs::read(entry.path().join("cmdline"))
            .is_ok_and(|cmdline| cmdline.split(|byte| *byte == 0).any(|arg| arg == marker.as_bytes()))
    };
    std::fs::read_dir("/proc").unwrap().flatten().filter(has_marker).count()
}

#[test]
fn a_command_leaves_nothing_running_when_it_returns_or_is_withdrawn() {
    // A duration no other test uses names each command's processes on the host.
    let marker = |seconds: u32| format!("{seconds}.{}", std::process::id());
    let (returned, withdrawn) = (marker(301), marker(302));
    // GNU `timeout` (and its sleep) in a process group of its own, a sleep
    // in a session of its own, both under way before the command goes on.
    // Newer GNU `timeout` (coreutils 9.11, for one) has its command sent
    // SIGTERM when it dies (PR_SET_PDEATHSIG); the sleep ignores it, so it
    // outlives `timeout` on every version and the sweep's next round finds it.
    let leave = |m: &str| {
        format!(
            "timeout {m} sh -c 'trap \"\" TERM; touch {m}.group && exec sleep {m}' & \
             setsid sh -c 'touch {m}.session && exec sleep {m}' & \
             until [ -e {m}.group ] && [ -e {m}.session ]; do sleep 0.01; done; "
        )
    };
    let exec = |command: String| -> Value {
        json!({"tool": "call", "endpoint": "shell", "action": "exec", "path": ["w"],
               "payload": {"command": command}})
    };
    let mut scenario = Scenario::new();
    scenario.add_shell_over("shell", "data");
    let calls = [
        exec(format!("{}echo started", leave(&returned))),
        exec(format!("{}sleep {withdrawn}", leave(&withdrawn))),
    ];
    scenario.add_agent("caller", &json!({"turns": [{"tool_calls": calls}]}), None);
    let supervisor = scenario.start();
    scenario.boot_service(&supervisor, "shell", "shell");
    let caller = supervisor.boot(program("caller"), vec![cap("shell", &["exec"], &[])]).unwrap();

    let first = scenario.wait_transcript("caller", 1);
    assert_eq!(ok_value(&first[0]).map(|reply| &reply["output"]), Some(&json!("started\n")), "{first:?}");
    assert_eq!(running(&returned), 0, "what a command started outlived its reply");
    // `timeout`, its sleep and the other session's sleep, which the answer counts.
    assert_eq!(ok_value(&first[0]).map(|reply| &reply["stopped_leftovers"]), Some(&json!(3)), "{first:?}");

    // `timeout`, its sleep, the other session's sleep and the command's own.
    assert!(wait_for(TIMEOUT, || running(&withdrawn) == 4), "the second command did not start");
    supervisor.terminate(caller);
    assert!(
        wait_for(TIMEOUT, || running(&withdrawn) == 0),
        "what a withdrawn command started outlived it: {} left",
        running(&withdrawn)
    );
}
