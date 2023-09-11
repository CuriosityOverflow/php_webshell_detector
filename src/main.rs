use regex::Regex;
use std::env;
use std::fs::File;
use std::io::{self, Read};

fn detect_php_webshell(file_path: &str) -> Result<(), io::Error> {
    // List of common PHP web shell signatures
    let webshell_signatures = vec![
        r#"<\?php\s+eval\("#,                           // Basic eval() function.
        r#"<\?php\s+eval\(base64_decode\("#,            // eval(base64_decode()) obfuscation.
        r#"<\?php\s+eval\(gzinflate\(base64_decode\("#,  // eval(gzinflate(base64_decode())) obfuscation.
        r#"<\?php\s+@eval\("#,                          // Suppressed eval() function.
        r#"<\?php\s+@eval\(base64_decode\("#,           // Suppressed eval(base64_decode()) obfuscation.
        r#"<\?php\s+system\("#,                        // Basic system() function.
        r#"<\?php\s+shell_exec\("#,                   // Basic shell_exec() function.
        r#"<\?php\s+passthru\("#,                    // Basic passthru() function.
        r#"<\?php\s+`.*`\s*;"#,                        // Command execution within backticks.
        r#"<\?php\s+(eval|assert)\(\$_(GET|POST|REQUEST)\["#,
        r#"<\?php\s+(@)?\$_(GET|POST|REQUEST)\["#,
        r#"<\?php\s+\$_(GET|POST|REQUEST)\["#,
        r#"<\?php\s+(eval|assert)\("#,                  // eval() or assert() with variable array access.
        r#"<\?php\s+(@)?\$_(GET|POST|REQUEST)\["#,
        r#"<\?php\s+\$_(GET|POST|REQUEST)\["#,
    ];

    let mut file = File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    for signature in webshell_signatures {
        let re = Regex::new(signature).unwrap();
        if re.is_match(&content) {
            println!("Web shell signature detected in {}:", file_path);
            println!("{}", signature);
            println!("---");
        }
    }

    Ok(())
}

fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        std::process::exit(1);
    }
    let file_to_scan = &args[1];
    detect_php_webshell(file_to_scan)?;

    Ok(())
}








