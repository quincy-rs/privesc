use std::{thread::sleep, time::Duration};

use privesc::PrivilegedCommand;

fn main() {
    // Spawn a privileged process without blocking
    let mut child = PrivilegedCommand::new("sleep").arg("2").spawn().unwrap();

    if let Some(id) = child.id() {
        println!("Spawned process with ID: {id}");
    }

    // Do some work while the process runs
    println!("Doing other work while process runs...");

    sleep(Duration::from_secs(1));

    // Check if the process has finished (non-blocking)
    match child.try_wait().unwrap() {
        Some(status) => println!("Process already finished with: {status}"),
        None => println!("Process still running..."),
    }

    // Wait for the process to complete
    println!("Waiting for process to finish...");
    let output = child.wait().unwrap();

    println!("Exit status: {}", output.status);
}
