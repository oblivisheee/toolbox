fn input(prefix: &str) -> String {
    use std::io::{self, Write};
    print!("{}", prefix);
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();
    buffer.trim().to_string()
}
