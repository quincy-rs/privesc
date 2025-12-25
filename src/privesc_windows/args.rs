//! Windows command-line argument escaping.
//!
//! This module provides functions for escaping command-line arguments on Windows,
//! following the conventions expected by `CommandLineToArgvW` for regular programs
//! and the special escaping rules required by cmd.exe for batch files.
//!
//! The implementations are adapted from the Rust standard library:
//! - <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/args/windows.rs>
//! - <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/process/windows.rs>

/// Appends an escaped argument to the command line.
///
/// This implementation is adapted from the Rust standard library's
/// `append_arg` function in `library/std/src/sys/args/windows.rs`:
/// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/args/windows.rs>
///
/// The escaping rules follow the conventions expected by `CommandLineToArgvW`:
/// - Arguments containing spaces or tabs are wrapped in double quotes
/// - Empty arguments are wrapped in double quotes
/// - Backslashes are literal unless followed by a double quote
/// - Backslashes immediately preceding a double quote are doubled, then the quote is escaped
/// - Trailing backslashes (before the closing quote) are doubled
fn append_arg(cmd: &mut String, arg: &str) {
    // Determine if quoting is needed: empty args, or args containing spaces/tabs
    let quote = arg.is_empty() || arg.bytes().any(|c| c == b' ' || c == b'\t');

    if quote {
        cmd.push('"');
    }

    let mut backslashes: usize = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else {
            if c == '"' {
                // Escape all backslashes and the quote itself
                // n backslashes followed by a quote -> 2n+1 backslashes followed by a quote
                cmd.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = 0;
        }
        cmd.push(c);
    }

    if quote {
        // Escape trailing backslashes before the closing quote
        // n trailing backslashes -> 2n backslashes
        cmd.extend(std::iter::repeat_n('\\', backslashes));
        cmd.push('"');
    }
}

/// Escapes and joins arguments into a single command-line string.
///
/// This follows the same approach as `make_command_line` in the Rust standard library:
/// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/process/windows.rs>
pub(super) fn escape_arguments(args: &[&str]) -> String {
    let mut cmd = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            cmd.push(' ');
        }
        append_arg(&mut cmd, arg);
    }
    cmd
}

/// Characters that are safe without quoting in batch files.
///
/// Rather than trying to find every ASCII symbol that must be quoted,
/// we assume all ASCII symbols must be quoted unless they're known to be safe.
const BAT_UNQUOTED_SAFE: &str = r"#$*+-./:?@\_";

/// The escape sequence used to prevent environment variable expansion in batch files.
///
/// This uses cmd.exe's substring syntax: `%cd:~,%` extracts a zero-length substring
/// from the built-in `cd` variable, effectively expanding to nothing. By inserting
/// this sequence, we break up any `%VAR%` patterns that might otherwise be expanded.
///
/// See: <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/args/windows.rs>
#[cfg_attr(not(test), allow(dead_code))]
const BAT_PERCENT_ESCAPE: &str = "%%cd:~,%";

/// Appends an escaped argument for batch file execution.
///
/// This implementation is adapted from the Rust standard library's
/// `append_bat_arg` function in `library/std/src/sys/args/windows.rs`:
/// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/args/windows.rs>
///
/// Batch file escaping differs from regular argument escaping because cmd.exe
/// uses different parsing rules than `CommandLineToArgvW`:
/// - Many more characters require quoting (anything not alphanumeric or in `#$*+-./:?@\_`)
/// - Empty arguments require quoting
/// - Trailing backslashes force quoting (to prevent escaping the closing quote)
/// - Control characters trigger quoting
/// - `%` and `\r` are escaped using `%%cd:~,%` to prevent environment variable expansion
/// - Quotes are escaped by doubling them (not with backslash)
fn append_bat_arg(cmd: &mut String, arg: &str) {
    // Empty arguments or arguments ending with backslash need quoting.
    // Trailing backslash would escape the closing quote otherwise.
    let mut quote = arg.is_empty() || arg.ends_with('\\');

    // Check if any character requires quoting
    if !quote {
        for c in arg.chars() {
            let needs_quotes = if c.is_ascii() {
                // Most ASCII symbols need quoting unless they're known safe
                !(c.is_ascii_alphanumeric() || BAT_UNQUOTED_SAFE.contains(c))
            } else {
                // Unicode control characters need quoting
                c.is_control()
            };
            if needs_quotes {
                quote = true;
                break;
            }
        }
    }

    if quote {
        cmd.push('"');
    }

    // Loop through the string, escaping `\` only if followed by `"`.
    // Escape `"` by doubling them. Escape `%` and `\r` to prevent variable expansion.
    let mut backslashes: usize = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
        } else {
            if c == '"' {
                // Add n backslashes to total 2n before internal `"`
                cmd.extend(std::iter::repeat_n('\\', backslashes));
                // Escape the quote by doubling it
                cmd.push('"');
            } else if c == '%' || c == '\r' {
                // Escape % and \r to prevent environment variable expansion.
                // This breaks up %VAR% patterns so they don't expand.
                cmd.push_str(BAT_PERCENT_ESCAPE);
            }
            backslashes = 0;
        }
        cmd.push(c);
    }

    if quote {
        // Add n backslashes to total 2n before ending `"`
        cmd.extend(std::iter::repeat_n('\\', backslashes));
        cmd.push('"');
    }
}

/// Escapes and joins arguments into a command-line string for batch file execution.
///
/// This follows the batch-specific escaping rules required by cmd.exe.
/// See `append_bat_arg` for details on the escaping rules.
pub(super) fn escape_bat_arguments(args: &[&str]) -> String {
    let mut cmd = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            cmd.push(' ');
        }
        append_bat_arg(&mut cmd, arg);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for argument escaping, adapted from the Rust standard library's
    /// `test_make_command_line` in `library/std/src/sys/process/windows/tests.rs`:
    /// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/process/windows/tests.rs>
    #[test]
    fn test_escape_arguments() {
        // Basic arguments without special characters
        assert_eq!(escape_arguments(&["aaa", "bbb", "ccc"]), "aaa bbb ccc");

        // Trailing backslashes (not before a quote, so literal)
        assert_eq!(escape_arguments(&[r"C:\"]), r"C:\");
        assert_eq!(escape_arguments(&[r"2slashes\\"]), r"2slashes\\");

        // Space triggers quoting, trailing backslashes must be doubled
        assert_eq!(escape_arguments(&[r" C:\"]), r#"" C:\\""#);
        assert_eq!(escape_arguments(&[r" 2slashes\\"]), r#"" 2slashes\\\\""#);

        // Arguments without spaces don't need quoting
        assert_eq!(escape_arguments(&["aaa"]), "aaa");

        // Wildcards and special chars preserved (no quoting needed)
        assert_eq!(escape_arguments(&["aaa", "v*"]), "aaa v*");

        // Embedded quotes are escaped with backslash
        assert_eq!(escape_arguments(&[r#"aa"bb"#]), r#"aa\"bb"#);

        // Arguments with spaces get quoted
        assert_eq!(escape_arguments(&["a b c"]), r#""a b c""#);

        // Complex escape sequences: quotes and backslashes
        // Input: `" \" \` and `\`
        // First arg has space so quoted: `"` -> `\"`, ` `, `\` before `"` -> `\\\"`, ` `, `\` trailing -> `\\`
        assert_eq!(escape_arguments(&[r#"" \" \"#, r"\"]), r#""\" \\\" \\" \"#);

        // Empty argument must be quoted
        assert_eq!(escape_arguments(&[""]), r#""""#);
        assert_eq!(escape_arguments(&["", ""]), r#""" """#);
        assert_eq!(escape_arguments(&["a", "", "b"]), r#"a "" b"#);

        // Tab also triggers quoting
        assert_eq!(escape_arguments(&["a\tb"]), "\"a\tb\"");

        // Unicode characters pass through unchanged
        assert_eq!(
            escape_arguments(&["\u{03c0}\u{042f}\u{97f3}\u{00e6}\u{221e}"]),
            "\u{03c0}\u{042f}\u{97f3}\u{00e6}\u{221e}"
        );

        // Multiple backslashes before a quote
        assert_eq!(escape_arguments(&[r#"a\\\"b"#]), r#"a\\\\\\\"b"#);

        // Backslashes not before a quote remain literal
        assert_eq!(escape_arguments(&[r"a\b\c"]), r"a\b\c");

        // Mixed: backslashes, then quote
        assert_eq!(escape_arguments(&[r#"a\"#, r#"b"c"#]), r#"a\ b\"c"#);
    }

    #[test]
    fn test_append_arg() {
        let mut cmd = String::new();
        append_arg(&mut cmd, "simple");
        assert_eq!(cmd, "simple");

        let mut cmd = String::new();
        append_arg(&mut cmd, "with space");
        assert_eq!(cmd, "\"with space\"");

        let mut cmd = String::new();
        append_arg(&mut cmd, "");
        assert_eq!(cmd, "\"\"");

        let mut cmd = String::new();
        append_arg(&mut cmd, r"path\to\file");
        assert_eq!(cmd, r"path\to\file");

        let mut cmd = String::new();
        append_arg(&mut cmd, r"path with\spaces\");
        assert_eq!(cmd, r#""path with\spaces\\""#);

        let mut cmd = String::new();
        append_arg(&mut cmd, r#"say "hello""#);
        assert_eq!(cmd, r#""say \"hello\"""#);
    }

    /// Tests for batch file argument escaping, adapted from the Rust standard library's
    /// `append_bat_arg` function in `library/std/src/sys/args/windows.rs`:
    /// <https://github.com/rust-lang/rust/blob/master/library/std/src/sys/args/windows.rs>
    ///
    /// See also CVE-2024-24576 for context on why this escaping is security-critical:
    /// <https://github.com/rust-lang/rust/security/advisories/GHSA-q455-m56c-85mh>
    #[test]
    fn test_escape_bat_arguments() {
        // Basic alphanumeric arguments don't need quoting
        assert_eq!(escape_bat_arguments(&["aaa", "bbb", "ccc"]), "aaa bbb ccc");
        assert_eq!(escape_bat_arguments(&["hello123"]), "hello123");

        // Safe special characters (from BAT_UNQUOTED_SAFE) don't need quoting
        assert_eq!(escape_bat_arguments(&["file.txt"]), "file.txt");
        assert_eq!(escape_bat_arguments(&["path/to/file"]), "path/to/file");
        assert_eq!(escape_bat_arguments(&["C:/Windows"]), "C:/Windows");
        assert_eq!(escape_bat_arguments(&["user@host"]), "user@host");
        assert_eq!(escape_bat_arguments(&["a+b"]), "a+b");
        assert_eq!(escape_bat_arguments(&["a-b"]), "a-b");
        assert_eq!(escape_bat_arguments(&["a*"]), "a*");
        assert_eq!(escape_bat_arguments(&["a?"]), "a?");
        assert_eq!(escape_bat_arguments(&["#tag"]), "#tag");
        assert_eq!(escape_bat_arguments(&["$var"]), "$var");

        // Spaces require quoting
        assert_eq!(escape_bat_arguments(&["a b c"]), r#""a b c""#);
        assert_eq!(escape_bat_arguments(&["hello world"]), r#""hello world""#);

        // Empty argument requires quoting
        assert_eq!(escape_bat_arguments(&[""]), r#""""#);
        assert_eq!(escape_bat_arguments(&["a", "", "b"]), r#"a "" b"#);

        // Trailing backslash forces quoting (prevents escaping the closing quote)
        assert_eq!(escape_bat_arguments(&[r"C:\"]), r#""C:\\""#);
        assert_eq!(escape_bat_arguments(&[r"path\"]), r#""path\\""#);
        assert_eq!(escape_bat_arguments(&[r"double\\"]), r#""double\\\\""#);

        // Backslashes in the middle don't need quoting if no other special chars
        assert_eq!(escape_bat_arguments(&[r"a\b\c"]), r"a\b\c");

        // Percent signs are escaped to prevent environment variable expansion
        // %VAR% would expand, so we insert %%cd:~,% before each %
        assert_eq!(
            escape_bat_arguments(&["%PATH%"]),
            format!(r#""{e}%PATH{e}%""#, e = BAT_PERCENT_ESCAPE)
        );
        assert_eq!(
            escape_bat_arguments(&["100%"]),
            format!(r#""100{e}%""#, e = BAT_PERCENT_ESCAPE)
        );

        // Carriage return is also escaped (same as percent)
        assert_eq!(
            escape_bat_arguments(&["line\rbreak"]),
            format!(r#""line{e}{cr}break""#, e = BAT_PERCENT_ESCAPE, cr = '\r')
        );

        // Quotes are escaped by doubling
        assert_eq!(
            escape_bat_arguments(&[r#"say "hello""#]),
            r#""say ""hello""""#
        );
        assert_eq!(escape_bat_arguments(&[r#"""#]), r#""""""#);

        // Backslash before quote: backslashes are doubled
        assert_eq!(escape_bat_arguments(&[r#"a\"b"#]), r#""a\\""b""#);
        assert_eq!(escape_bat_arguments(&[r#"a\\"b"#]), r#""a\\\\""b""#);

        // Various special characters that require quoting
        assert_eq!(escape_bat_arguments(&["a&b"]), r#""a&b""#);
        assert_eq!(escape_bat_arguments(&["a|b"]), r#""a|b""#);
        assert_eq!(escape_bat_arguments(&["a<b"]), r#""a<b""#);
        assert_eq!(escape_bat_arguments(&["a>b"]), r#""a>b""#);
        assert_eq!(escape_bat_arguments(&["a^b"]), r#""a^b""#);
        assert_eq!(escape_bat_arguments(&["a(b)"]), r#""a(b)""#);
        assert_eq!(escape_bat_arguments(&["a;b"]), r#""a;b""#);
        assert_eq!(escape_bat_arguments(&["a,b"]), r#""a,b""#);
        assert_eq!(escape_bat_arguments(&["a=b"]), r#""a=b""#);
        assert_eq!(escape_bat_arguments(&["a!b"]), r#""a!b""#);
        assert_eq!(escape_bat_arguments(&["a`b"]), r#""a`b""#);
        assert_eq!(escape_bat_arguments(&["a'b"]), r#""a'b""#);
        assert_eq!(escape_bat_arguments(&["a[b]"]), r#""a[b]""#);
        assert_eq!(escape_bat_arguments(&["a{b}"]), r#""a{b}""#);
        assert_eq!(escape_bat_arguments(&["a~b"]), r#""a~b""#);

        // Tab requires quoting
        assert_eq!(escape_bat_arguments(&["a\tb"]), "\"a\tb\"");

        // Unicode characters pass through unchanged (only ASCII control chars need quoting)
        assert_eq!(
            escape_bat_arguments(&["\u{03c0}\u{042f}\u{97f3}"]),
            "\u{03c0}\u{042f}\u{97f3}"
        );

        // Control characters trigger quoting
        assert_eq!(escape_bat_arguments(&["a\x01b"]), "\"a\x01b\"");
        assert_eq!(escape_bat_arguments(&["a\nb"]), "\"a\nb\"");

        // Complex case: multiple special chars
        assert_eq!(
            escape_bat_arguments(&["hello world", r"C:\path\", "%VAR%"]),
            format!(
                r#""hello world" "C:\path\\" "{e}%VAR{e}%""#,
                e = BAT_PERCENT_ESCAPE
            )
        );
    }

    #[test]
    fn test_append_bat_arg() {
        let mut cmd = String::new();
        append_bat_arg(&mut cmd, "simple");
        assert_eq!(cmd, "simple");

        let mut cmd = String::new();
        append_bat_arg(&mut cmd, "with space");
        assert_eq!(cmd, "\"with space\"");

        let mut cmd = String::new();
        append_bat_arg(&mut cmd, "");
        assert_eq!(cmd, "\"\"");

        let mut cmd = String::new();
        append_bat_arg(&mut cmd, r"trailing\");
        assert_eq!(cmd, r#""trailing\\""#);

        let mut cmd = String::new();
        append_bat_arg(&mut cmd, "%VAR%");
        assert_eq!(cmd, format!(r#""{e}%VAR{e}%""#, e = BAT_PERCENT_ESCAPE));

        let mut cmd = String::new();
        append_bat_arg(&mut cmd, r#"say "hi""#);
        assert_eq!(cmd, r#""say ""hi""""#);
    }

    /// Test that batch escaping prevents command injection via environment variables.
    /// This is the key security property addressed by CVE-2024-24576.
    #[test]
    fn test_bat_escaping_prevents_injection() {
        // An attacker trying to inject %PATH% should get it escaped
        let escaped = escape_bat_arguments(&["%PATH%"]);
        assert!(!escaped.contains("%PATH%") || escaped.contains(BAT_PERCENT_ESCAPE));

        // An attacker trying to inject %COMSPEC% /c malicious
        let escaped = escape_bat_arguments(&["%COMSPEC%", "/c", "malicious"]);
        assert!(escaped.contains(BAT_PERCENT_ESCAPE));

        // Nested percent signs
        let escaped = escape_bat_arguments(&["%%nested%%"]);
        // Each % should be preceded by the escape sequence
        assert!(escaped.matches(BAT_PERCENT_ESCAPE).count() >= 4);
    }
}
