use clap::{Parser, Subcommand};
use colored::*;
use std::path::{Path, PathBuf};
use std::fs;
use sanctifier_core::{Analyzer, ArithmeticIssue, SizeWarning, UnsafePattern, PatternType};
use syn;

#[derive(Parser)]
#[command(name = "sanctifier")]
#[command(about = "Stellar Soroban Security & Formal Verification Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Soroban contract for vulnerabilities
    Analyze {
        /// Path to the contract directory or Cargo.toml
        #[arg(default_value = ".")]
        path: PathBuf,
        
        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Limit for ledger entry size in bytes
        #[arg(short, long, default_value = "64000")]
        limit: usize,
    },
    /// Generate a security report
    Report {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
  /// Initialize Sanctifier in a new project
    Init,
    /// Analyze contract complexity metrics
    Complexity {
        /// Path to contract directory or .rs file
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format (text, json, html)
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Write report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}


fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Analyze { path, format, limit } => {
            let is_json = format == "json";

            if !is_soroban_project(path) {
                eprintln!("{} Error: {:?} is not a valid Soroban project. (Missing Cargo.toml with 'soroban-sdk' dependency)", "❌".red(), path);
                std::process::exit(1);
            }

            // In JSON mode, send informational lines to stderr so stdout is clean JSON.
            if is_json {
                eprintln!("{} Sanctifier: Valid Soroban project found at {:?}", "✨".green(), path);
                eprintln!("{} Analyzing contract at {:?}...", "🔍".blue(), path);
            } else {
                println!("{} Sanctifier: Valid Soroban project found at {:?}", "✨".green(), path);
                println!("{} Analyzing contract at {:?}...", "🔍".blue(), path);
            }
            
            let mut analyzer = Analyzer::new(false);
            analyzer.ledger_limit = *limit;
            
            let mut all_size_warnings: Vec<SizeWarning> = Vec::new();
            let mut all_unsafe_patterns: Vec<UnsafePattern> = Vec::new();
            let mut all_auth_gaps: Vec<String> = Vec::new();
            let mut all_panic_issues = Vec::new();
            let mut all_arithmetic_issues: Vec<ArithmeticIssue> = Vec::new();

            if path.is_dir() {
                analyze_directory(path, &analyzer, &mut all_size_warnings, &mut all_unsafe_patterns, &mut all_auth_gaps, &mut all_panic_issues, &mut all_arithmetic_issues);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                if let Ok(content) = fs::read_to_string(path) {
                    all_size_warnings.extend(analyzer.analyze_ledger_size(&content));

                    let patterns = analyzer.analyze_unsafe_patterns(&content);
                    for mut p in patterns {
                        p.snippet = format!("{}: {}", path.display(), p.snippet);
                        all_unsafe_patterns.push(p);
                    }

                    let gaps = analyzer.scan_auth_gaps(&content);
                    for g in gaps {
                        all_auth_gaps.push(format!("{}: {}", path.display(), g));
                    }

                    let panics = analyzer.scan_panics(&content);
                    for p in panics {
                        let mut p_mod = p.clone();
                        p_mod.location = format!("{}: {}", path.display(), p.location);
                        all_panic_issues.push(p_mod);
                    }

                    let arith = analyzer.scan_arithmetic_overflow(&content);
                    for mut a in arith {
                        a.location = format!("{}: {}", path.display(), a.location);
                        all_arithmetic_issues.push(a);
                    }
                }
            }

            if is_json {
                eprintln!("{} Static analysis complete.", "✅".green());
            } else {
                println!("{} Static analysis complete.", "✅".green());
            }
            
            if format == "json" {
                let output = serde_json::json!({
                    "size_warnings": all_size_warnings,
                    "unsafe_patterns": all_unsafe_patterns,
                    "auth_gaps": all_auth_gaps,
                    "panic_issues": all_panic_issues,
                    "arithmetic_issues": all_arithmetic_issues,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string()));
            } else {
                if all_warnings.is_empty() {
                    println!("No ledger size issues found.");
                } else {
                    for warning in all_warnings {
                        println!(
                            "{} Warning: Struct {} is approaching ledger entry size limit!",
                            "⚠️".yellow(),
                            warning.struct_name.bold()
                        );
                        println!(
                            "   Estimated size: {} bytes (Limit: {} bytes)",
                            warning.estimated_size.to_string().red(),
                            warning.limit
                        );
                    }
                }

                if !all_auth_gaps.is_empty() {
                    println!("\n{} Found potential Authentication Gaps!", "🛑".red());
                    for gap in all_auth_gaps {
                        println!("   {} Function {} is modifying state without require_auth()", "->".red(), gap.bold());
                    }
                } else {
                    println!("\nNo authentication gaps found.");
                }

                if !all_panic_issues.is_empty() {
                    println!("\n{} Found explicit Panics/Unwraps!", "🛑".red());
                    for issue in all_panic_issues {
                        println!(
                            "   {} Function {}: Using {} (Location: {})",
                            "->".red(),
                            issue.function_name.bold(),
                            issue.issue_type.yellow().bold(),
                            issue.location
                        );
                    }
                    println!("   {} Tip: Prefer returning Result or Error types for better contract safety.", "💡".blue());
                } else {
                    println!("\nNo panic/unwrap issues found.");
                }

                if !all_arithmetic_issues.is_empty() {
                    println!("\n{} Found unchecked Arithmetic Operations!", "🔢".yellow());
                    for issue in all_arithmetic_issues {
                        println!(
                            "   {} Function {}: Unchecked `{}` ({})",
                            "->".red(),
                            issue.function_name.bold(),
                            issue.operation.yellow().bold(),
                            issue.location
                        );
                        println!("      {} {}", "💡".blue(), issue.suggestion);
                    }
                } else {
                    println!("\nNo arithmetic overflow risks found.");
                }
            }
        },
        Commands::Report { output } => {
            println!("{} Generating report...", "📄".yellow());
            if let Some(p) = output {
                println!("Report saved to {:?}", p);
            } else {
                println!("Report printed to stdout.");
            }
        },
        Commands::Init => {
            println!("{} Initializing Sanctifier configuration...", "⚙️".cyan());
            println!("Created .sanctify.toml");
        },
        Commands::Complexity { path, format, output } => {
            use sanctifier_core::complexity;
            use std::fs;

            println!("{} Analyzing complexity at {:?}...", "📊".blue(), path);

            let mut all_functions = Vec::new();
            let mut total_deps = 0;

            let rs_files = collect_rs_files(path);
            for file_path in &rs_files {
                if let Ok(source) = fs::read_to_string(file_path) {
                    if let Ok(ast) = syn::parse_file(&source) {
                        let m = complexity::analyze_complexity(&ast, &file_path.display().to_string());
                        total_deps += m.dependency_count;
                        all_functions.extend(m.functions);
                    }
                }
            }

            let combined = complexity::ContractMetrics {
                contract_path: path.display().to_string(),
                dependency_count: total_deps,
                functions: all_functions,
            };

            let report = match format.as_str() {
                "json" => complexity::render_json_report(&combined),
                "html" => complexity::render_html_report(&combined),
                _      => complexity::render_text_report(&combined),
            };

            if let Some(out_path) = output {
                fs::write(out_path, &report).expect("Failed to write report");
                println!("{} Report written to {:?}", "✅".green(), out_path);
            } else {
                println!("{}", report);
            }

            let has_warnings = combined.functions.iter().any(|f| !f.warnings.is_empty());
            if has_warnings { std::process::exit(1); }
        }
    }
}

fn is_soroban_project(path: &Path) -> bool {
    let cargo_toml_path = if path.is_dir() {
        path.join("Cargo.toml")
    } else if path.file_name().and_then(|s| s.to_str()) == Some("Cargo.toml") {
        path.to_path_buf()
    } else {
        // If it's a .rs file, look for Cargo.toml in parent directories
        let mut current = path.parent();
        let mut found = None;
        while let Some(p) = current {
            let cargo = p.join("Cargo.toml");
            if cargo.exists() {
                found = Some(cargo);
                break;
            }
            current = p.parent();
        }
        match found {
            Some(f) => f,
            None => return false,
        }
    };

    if !cargo_toml_path.exists() {
        return false;
    }

    if let Ok(content) = fs::read_to_string(cargo_toml_path) {
        content.contains("soroban-sdk")
    } else {
        false
    }
}

fn analyze_directory(
    dir: &Path,
    analyzer: &Analyzer,
    all_size_warnings: &mut Vec<SizeWarning>,
    all_unsafe_patterns: &mut Vec<UnsafePattern>,
    all_auth_gaps: &mut Vec<String>,
    all_panic_issues: &mut Vec<sanctifier_core::PanicIssue>,
    all_arithmetic_issues: &mut Vec<ArithmeticIssue>,
) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                analyze_directory(&path, analyzer, all_size_warnings, all_unsafe_patterns, all_auth_gaps, all_panic_issues, all_arithmetic_issues);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let warnings = analyzer.analyze_ledger_size(&content);
                    for mut w in warnings {
                        w.struct_name = format!("{}: {}", path.display(), w.struct_name);
                        all_warnings.push(w);
                    }

                    let gaps = analyzer.scan_auth_gaps(&content);
                    for g in gaps {
                        all_auth_gaps.push(format!("{}: {}", path.display(), g));
                    }

                    let panics = analyzer.scan_panics(&content);
                    for p in panics {
                        let mut p_mod = p.clone();
                        p_mod.location = format!("{}: {}", path.display(), p.location);
                        all_panic_issues.push(p_mod);
                    }

                    let arith = analyzer.scan_arithmetic_overflow(&content);
                    for mut a in arith {
                        a.location = format!("{}: {}", path.display(), a.location);
                        all_arithmetic_issues.push(a);
                    }
                }
            }
        }
        fn collect_rs_files(path: &PathBuf) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if path.is_file() && path.extension().map_or(false, |e| e == "rs") {
        files.push(path.clone());
    } else if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                if p.is_dir() && name != "target" && name != ".git" {
                    files.extend(collect_rs_files(&p));
                } else if p.extension().map_or(false, |e| e == "rs") {
                    files.push(p);
                }
            }
        }
    }
    files
}
    }
    
}
