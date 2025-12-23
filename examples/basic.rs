use privesc::PrivilegedCommand;

fn main() {
    let output = PrivilegedCommand::new("cat")
        .arg("/etc/shadow")
        .gui(true)
        .prompt("Administrator privileges required to read the test file")
        .run()
        .unwrap();

    println!("Exit status: {}", output.status);

    match output.stdout_str() {
        Some(stdout) => println!("Out: {stdout}"),
        None => println!("Out: <not available on this platform>"),
    }

    match output.stderr_str() {
        Some(stderr) => println!("Err: {stderr}"),
        None => println!("Err: <not available on this platform>"),
    }
}
