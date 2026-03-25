# Contributing to Sanctifier

Thank you for contributing to Sanctifier! This guide covers the two most common contributions: adding a new detector rule and adding a new finding type.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Adding a New Detector Rule](#adding-a-new-detector-rule)
- [Adding a New Finding Type](#adding-a-new-finding-type)
- [Testing Requirements](#testing-requirements)
- [PR Checklist](#pr-checklist)

---

## Prerequisites

```bash
# Clone and enter the repo
git clone https://github.com/<your-fork>/Sanctifier.git
cd Sanctifier

# Verify the build passes
cargo test -p sanctifier-core -p sanctifier-cli --all-features
cargo clippy -p sanctifier-core -p sanctifier-cli --all-features -- -D warnings
cargo fmt --check
```

---

## Adding a New Detector Rule

A detector rule is a method on `Analyzer` in `tooling/sanctifier-core/src/lib.rs` that takes a `&str` of Rust source and returns a `Vec` of findings.

### Step 1 — Define a finding struct

Open `tooling/sanctifier-core/src/lib.rs` and add a public struct for your finding alongside the existing ones (e.g. near `ArithmeticIssue`):

```rust
/// Represents a <describe what the detector catches>.
#[derive(Debug, Serialize, Clone)]
pub struct MyIssue {
    /// Name of the function containing the issue.
    pub function_name: String,
    /// Human-readable description of the problem.
    pub message: String,
    /// "function_name:line" context string.
    pub location: String,
}
```

### Step 2 — Implement the detector method

Add a public method and a private `_impl` method to `impl Analyzer`. Follow the existing pattern exactly — the public method wraps the impl in `with_panic_guard` so a malformed source file never crashes the process:

```rust
/// Detects <what your rule catches>.
///
/// Returns one `MyIssue` per finding. Returns an empty vec when the source
/// cannot be parsed (never panics).
pub fn scan_my_rule(&self, source: &str) -> Vec<MyIssue> {
    with_panic_guard(|| self.scan_my_rule_impl(source))
}

fn scan_my_rule_impl(&self, source: &str) -> Vec<MyIssue> {
    let file = match syn::parse_str::<syn::File>(source) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let mut issues = Vec::new();

    for item in &file.items {
        if let syn::Item::Impl(impl_block) = item {
            for item in &impl_block.items {
                if let syn::ImplItem::Fn(method) = item {
                    let fn_name = method.sig.ident.to_string();

                    // ── your detection logic here ──────────────────────────
                    // Example: flag any function named "dangerous"
                    if fn_name.contains("dangerous") {
                        issues.push(MyIssue {
                            function_name: fn_name.clone(),
                            message: "Function name contains 'dangerous'".to_string(),
                            location: format!("{}:0", fn_name),
                        });
                    }
                    // ──────────────────────────────────────────────────────
                }
            }
        }
    }

    issues
}
```

### Step 3 — Register the rule name in `default_enabled_rules`

In `tooling/sanctifier-core/src/lib.rs`, find `default_enabled_rules` and append your rule's identifier string:

```rust
fn default_enabled_rules() -> Vec<String> {
    vec![
        "auth_gaps".to_string(),
        "panics".to_string(),
        "arithmetic".to_string(),
        "ledger_size".to_string(),
        "events".to_string(),
        "my_rule".to_string(), // ← add this line
    ]
}
```

### Step 4 — Wire the detector into the CLI

Open `tooling/sanctifier-cli/src/commands/analyze.rs`.

**4a.** Add a new accumulator in `exec`:

```rust
let mut my_issues: Vec<sanctifier_core::MyIssue> = Vec::new();
```

**4b.** Pass it through `walk_dir` (add the parameter to the function signature and every call site):

```rust
fn walk_dir(
    // ... existing params ...
    my_issues: &mut Vec<sanctifier_core::MyIssue>,
) -> anyhow::Result<()> {
```

**4c.** Inside `walk_dir`, call the new method on each file:

```rust
my_issues.extend(analyzer.scan_my_rule(&content));
```

**4d.** Print the results in the text/JSON output block alongside the other findings.

---

## Adding a New Finding Type

If you only need to add a new struct without a full detector (e.g. a sub-category of an existing detector):

1. Define the struct in `tooling/sanctifier-core/src/lib.rs` with `#[derive(Debug, Serialize, Clone)]`.
2. Add `pub` visibility so the CLI crate can import it.
3. If the finding needs a rule-name string (for `SanctifyConfig.enabled_rules`), add a `const` near the top of `lib.rs`:

```rust
pub const RULE_MY_FINDING: &str = "my_finding";
```

4. Reference `RULE_MY_FINDING` inside `default_enabled_rules()` and wherever the rule is checked.

---

## Testing Requirements

All new detectors **must** include at least three tests and a false-positive check. Add them inside the existing `#[cfg(test)]` block at the bottom of `tooling/sanctifier-core/src/lib.rs`.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Test 1 — basic detection
    #[test]
    fn test_scan_my_rule_detects_issue() {
        let analyzer = Analyzer::new(SanctifyConfig::default());
        let source = r#"
            pub struct MyContract;
            impl MyContract {
                pub fn dangerous_transfer(e: Env) {}
            }
        "#;
        let issues = analyzer.scan_my_rule(source);
        assert!(!issues.is_empty(), "should detect the issue");
        assert_eq!(issues[0].function_name, "dangerous_transfer");
    }

    // Test 2 — edge case / variant
    #[test]
    fn test_scan_my_rule_detects_variant() {
        let analyzer = Analyzer::new(SanctifyConfig::default());
        let source = r#"
            pub struct MyContract;
            impl MyContract {
                pub fn dangerous_withdraw(e: Env, amount: i128) {}
            }
        "#;
        let issues = analyzer.scan_my_rule(source);
        assert_eq!(issues.len(), 1);
    }

    // Test 3 — invalid source does not panic
    #[test]
    fn test_scan_my_rule_invalid_source_no_panic() {
        let analyzer = Analyzer::new(SanctifyConfig::default());
        let issues = analyzer.scan_my_rule("this is not valid rust {{{");
        assert!(issues.is_empty());
    }

    // Test 4 — false-positive check (REQUIRED)
    #[test]
    fn test_scan_my_rule_no_false_positive() {
        let analyzer = Analyzer::new(SanctifyConfig::default());
        let source = r#"
            pub struct MyContract;
            impl MyContract {
                pub fn safe_transfer(e: Env) {}
            }
        "#;
        let issues = analyzer.scan_my_rule(source);
        assert!(issues.is_empty(), "safe code must not be flagged");
    }
}
```

Run the full test suite before opening a PR:

```bash
cargo test -p sanctifier-core --all-features
```

---

## PR Checklist

- [ ] `cargo fmt` applied — `cargo fmt -p sanctifier-core -p sanctifier-cli`
- [ ] Zero Clippy warnings — `cargo clippy -p sanctifier-core -p sanctifier-cli --all-features -- -D warnings`
- [ ] All new public items have a `///` doc comment
- [ ] At least 3 tests + 1 false-positive test for the new detector
- [ ] Rule name added to `default_enabled_rules()` in `lib.rs`
- [ ] CLI wired up in `analyze.rs` (finding collected and printed)
- [ ] PR description references the issue number (`Closes #NNN`)
