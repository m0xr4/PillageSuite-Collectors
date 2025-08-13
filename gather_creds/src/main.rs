use clap::Parser;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use anyhow::{Context, Result};
use chrono::Utc;

#[derive(Parser)]
#[command(name = "gather_creds")]
#[command(about = "Search for strings in files across UNC paths")]
struct Args {
    /// File containing search strings (one per line)
    #[arg(short, long)]
    search_strings: String,

    /// File containing UNC paths to search (one per line)
    #[arg(short, long)]
    files_to_search: String,

    /// Output directory for results
    #[arg(short, long)]
    output_dir: String,

    /// Perform ASCII case-insensitive matching
    #[arg(short = 'i', long)]
    ignore_case: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read search strings
    let search_strings = read_lines(&args.search_strings)?;
    println!("Loaded {} search strings", search_strings.len());

    // Read file paths
    let file_paths = read_lines(&args.files_to_search)?;
    println!("Loaded {} file paths to search", file_paths.len());

    // Create output directory if it doesn't exist
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("Failed to create output directory: {}", args.output_dir))?;

    // Build Aho–Corasick automaton once
    let ac = build_automaton(&search_strings, args.ignore_case)?;
    let mut total_files_processed = 0;
    let mut total_files_with_hits = 0;
    let mut file_results = Vec::new();

    // Process each file
    for file_path in file_paths {
        total_files_processed += 1;
        
        match search_file(&file_path, &ac) {
            Ok(hits) => {
                if !hits.is_empty() {
                    total_files_with_hits += 1;
                    
                    // Print file header to console
                    println!("=== Hits in: {} ===", file_path);

                    // Store results for HTML generation
                    file_results.push((file_path.clone(), hits));
                }
            }
            Err(e) => {
                eprintln!("Error processing file {}: {}", file_path, e);
            }
        }

        // Progress indicator
        if total_files_processed % 100 == 0 {
            println!("Processed {} files...", total_files_processed);
        }
    }

    println!("\n=== Search Complete ===");
    println!("Total files processed: {}", total_files_processed);
    println!("Files with hits: {}", total_files_with_hits);

    // Generate HTML report
    if !file_results.is_empty() {
        generate_html_report(
            &file_results,
            &search_strings,
            total_files_processed,
            total_files_with_hits,
            &args.output_dir,
        )?;
    }

    Ok(())
}

fn read_lines(filename: &str) -> Result<Vec<String>> {
    let file = File::open(filename)
        .with_context(|| format!("Failed to open file: {}", filename))?;
    
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    
    for line in reader.lines() {
        let line = line.with_context(|| "Failed to read line")?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_string());
        }
    }
    
    Ok(lines)
}

fn search_file(file_path: &str, ac: &AhoCorasick) -> Result<Vec<String>> {
    let file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to open file {}: {}", file_path, e));
        }
    };

    let reader = BufReader::new(file);
    let mut hits = Vec::new();

    // Read all lines into memory to get context
    let lines: Vec<String> = reader.lines()
        .map(|line| line.unwrap_or_else(|_| String::new()))
        .collect();

    for (line_num, line) in lines.iter().enumerate() {
        // Check if any search pattern is found in this line
        if ac.find(line).is_some() {
            let mut context = String::new();

            // Add line before (if not first line)
            if line_num > 0 {
                let before_line = highlight_line(&lines[line_num - 1], ac);
                context.push_str(&format!(
                    "<div class=\"line line-before\"><span class=\"line-number\">{}</span>{}</div>",
                    line_num,
                    before_line
                ));
            }

            // Add the hit line with highlighting
            let highlighted_line = highlight_line(line, ac);
            context.push_str(&format!(
                "<div class=\"line line-hit\"><span class=\"line-number\">{}</span>{} <span class=\"hit-marker\">&lt;-- HIT</span></div>",
                line_num + 1,
                highlighted_line
            ));

            // Add line after (if not last line)
            if line_num < lines.len() - 1 {
                let after_line = highlight_line(&lines[line_num + 1], ac);
                context.push_str(&format!(
                    "<div class=\"line line-after\"><span class=\"line-number\">{}</span>{}</div>",
                    line_num + 2,
                    after_line
                ));
            }

            hits.push(context);
        }
    }

    Ok(hits)
}

fn generate_html_report(
    file_results: &[(String, Vec<String>)],
    search_strings: &[String],
    total_files_processed: usize,
    total_files_with_hits: usize,
    output_dir: &str,
) -> Result<()> {
    // HTML template embedded as a string
    let template = r#"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Pillage Suite - Credential Gathering Results</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .summary {
            background-color: #e8f4fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .file-entry {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .file-header {
            background-color: #f8f9fa;
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
            font-weight: bold;
            color: #495057;
        }
        .file-content {
            padding: 15px;
            background-color: #fafafa;
        }
        .line {
            font-family: 'Courier New', monospace;
            margin: 2px 0;
            padding: 2px 5px;
            border-radius: 3px;
        }
        .line-hit {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
        }
        .line-before, .line-after {
            background-color: #f8f9fa;
            color: #6c757d;
        }
        .highlight {
            background-color: #ffeb3b;
            padding: 1px 2px;
            border-radius: 2px;
            font-weight: bold;
        }
        .line-number {
            color: #6c757d;
            font-weight: normal;
            margin-right: 10px;
        }
        .hit-marker {
            color: #dc3545;
            font-weight: bold;
        }
        .app-logo {
            width: 48px;
            height: 48px;
            margin-right: 15px;
            color: #1e293b;
        }
        .title-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 30px;
        }
        .footer {
            margin-top: 40px;
            padding: 20px;
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 14px;
        }
        .footer a {
            color: #495057;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class='container'>
        <div class='title-container'>
            <svg class='app-logo' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>
                <!-- Folder -->
                <path d='M22 5h-9l-2-2H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h19c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2z' transform='scale(0.92) translate(1, 1)' fill='currentColor'/>
                <!-- Share Icon based on svgrepo reference -->
                <g transform='translate(6.5, 7) scale(0.025)' fill='#e8f4fd' fill-opacity='0.8'>
                    <path d='M339.588,314.529c-14.215,0-27.456,4.133-38.621,11.239l-112.682-78.67c1.809-6.315,2.798-12.976,2.798-19.871    c0-6.896-0.989-13.557-2.798-19.871l109.64-76.547c11.764,8.356,26.133,13.286,41.662,13.286c39.79,0,72.047-32.257,72.047-72.047    C411.634,32.258,379.378,0,339.588,0c-39.79,0-72.047,32.257-72.047,72.047c0,5.255,0.578,10.373,1.646,15.308l-112.424,78.491    c-10.974-6.759-23.892-10.666-37.727-10.666c-39.79,0-72.047,32.257-72.047,72.047s32.256,72.047,72.047,72.047    c13.834,0,26.753-3.907,37.727-10.666l113.292,79.097c-1.629,6.017-2.514,12.34-2.514,18.872c0,39.79,32.257,72.047,72.047,72.047    c39.79,0,72.047-32.257,72.047-72.047C411.635,346.787,379.378,314.529,339.588,314.529z'/>
                </g>
            </svg>
            <h1>Pillage Suite - Credential Gathering Results</h1>
        </div>
        
        <div class='summary'>
            <h3>Summary</h3>
            <p><strong>Total files processed:</strong> {{TOTAL_FILES_PROCESSED}}</p>
            <p><strong>Files with hits:</strong> {{FILES_WITH_HITS}}</p>
            <p><strong>Search strings:</strong> {{SEARCH_STRINGS}}</p>
            <p><strong>Generated:</strong> {{GENERATED_TIMESTAMP}}</p>
        </div>

        {{FILE_ENTRIES}}
    </div>
    
    <div class='footer'>
        This report was created with <strong>Pillage Suite</strong> - <a href='https://github.com/m0xr4/PillageSuite' target='_blank'>https://github.com/m0xr4/PillageSuite</a></div>
    </body>
    </html>
"#;

    // Generate file entries HTML
    let mut file_entries_html = String::new();
    
    for (file_path, hits) in file_results {
        file_entries_html.push_str(&format!(
            r#"<div class="file-entry">
                <div class="file-header">{}</div>
                <div class="file-content">"#,
            html_escape(file_path)
        ));

        for hit in hits {
            file_entries_html.push_str(&hit);
        }

        file_entries_html.push_str("</div></div>");
    }

    // Replace template placeholders
    let html_content = template
        .replace("{{TOTAL_FILES_PROCESSED}}", &total_files_processed.to_string())
        .replace("{{FILES_WITH_HITS}}", &total_files_with_hits.to_string())
        .replace("{{SEARCH_STRINGS}}", &search_strings.join(", "))
        .replace("{{GENERATED_TIMESTAMP}}", &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .replace("{{FILE_ENTRIES}}", &file_entries_html);

    // Write HTML file with timestamp
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let html_filename = format!("search_results_{}.html", timestamp);
    let html_file_path = Path::new(output_dir).join(html_filename);
    fs::write(&html_file_path, html_content)
        .with_context(|| format!("Failed to write HTML file: {:?}", html_file_path))?;

    println!("HTML report written to: {:?}", html_file_path);
    Ok(())
}

fn html_escape(text: &str) -> String {
    text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}

fn highlight_line(line: &str, ac: &AhoCorasick) -> String {
    let mut result = String::new();
    let mut last_index = 0usize;

    for mat in ac.find_iter(line) {
        let start = mat.start();
        let end = mat.end();

        if start > last_index {
            result.push_str(&html_escape(&line[last_index..start]));
        }

        result.push_str("<span class=\"highlight\">");
        result.push_str(&html_escape(&line[start..end]));
        result.push_str("</span>");

        last_index = end;
    }

    if last_index < line.len() {
        result.push_str(&html_escape(&line[last_index..]));
    }

    if result.is_empty() {
        // No matches, just escape
        html_escape(line)
    } else {
        result
    }
}

fn build_automaton(patterns: &[String], ignore_case: bool) -> Result<AhoCorasick> {
    let mut builder = AhoCorasickBuilder::new();
    builder.match_kind(MatchKind::LeftmostLongest);
    builder.ascii_case_insensitive(ignore_case);

    Ok(builder.build(patterns)?)
}
