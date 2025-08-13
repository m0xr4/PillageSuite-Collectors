// Modules and imports for better organization
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process,
    ptr::null_mut,
    slice,
    time::SystemTime,
};

use chrono;
use serde_json;
use serde::Serialize;
use windows::{
    core::{PCWSTR, Result as WinResult},
    Win32::{
        Storage::FileSystem::{
            NetShareEnum, SHARE_INFO_0
        },
        NetworkManagement::NetManagement::{
            NetApiBufferFree
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION,
            GetAce, GetFileSecurityW, GetSecurityDescriptorDacl, GROUP_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        },
    },
};

// External Windows API definitions
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hMem: isize) -> isize;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut *mut u16) -> i32;
}

//========================================================================
// CONFIG AND CLI PARSING
//========================================================================

/// Configuration struct to hold all program arguments
#[derive(Debug)]
struct Config {
    target_or_file: String,
    max_depth: usize,
    output_path: String,
    max_entries: Option<usize>,
    debug_mode: bool,
    share_enum_only: bool,
    shares_file: Option<String>,
}

impl Config {
    /// Parse command line arguments into a Config struct
    fn from_args() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();
        
        if args.len() < 2 {
            return Err(get_help(&args[0]));
        }

        let mut config = Config {
            target_or_file: String::new(),
            max_depth: 3,
            output_path: "indexed_shares.jsonl".to_string(),
            max_entries: Some(5000),
            debug_mode: false,
            share_enum_only: false,
            shares_file: None,
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    return Err(get_help(&args[0]));
                }
                "--target" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--target requires a value".to_string());
                    }
                    config.target_or_file = args[i].clone();
                }
                "--max-depth" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--max-depth requires a value".to_string());
                    }
                    config.max_depth = args[i].parse()
                        .map_err(|_| format!("Invalid max-depth value: {}", args[i]))?;
                }
                "--output" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--output requires a value".to_string());
                    }
                    config.output_path = args[i].clone();
                }
                "--max-entries" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--max-entries requires a value".to_string());
                    }
                    config.max_entries = Some(args[i].parse()
                        .map_err(|_| format!("Invalid max-entries value: {}", args[i]))?);
                }
                "--debug" => {
                    config.debug_mode = true;
                }
                "--share-enum" => {
                    config.share_enum_only = true;
                }
                "--shares" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--shares requires a value".to_string());
                    }
                    config.shares_file = Some(args[i].clone());
                }
                arg if arg.starts_with('-') => {
                    return Err(format!("Unknown argument: {}", arg));
                }
                _ => {
                    // If no --target was specified, treat the first non-flag argument as target
                    if config.target_or_file.is_empty() {
                        config.target_or_file = args[i].clone();
                    } else {
                        return Err(format!("Unexpected argument: {}", args[i]));
                    }
                }
            }
            i += 1;
        }

        // Validate that either --target or --shares is provided, but not both
        if config.target_or_file.is_empty() && config.shares_file.is_none() {
            return Err("Either --target or --shares argument is required".to_string());
        }
        
        if !config.target_or_file.is_empty() && config.shares_file.is_some() {
            return Err("Cannot use both --target and --shares arguments".to_string());
        }
        
        // If using --shares, --target is not required
        if config.shares_file.is_some() && config.target_or_file.is_empty() {
            config.target_or_file = "N/A".to_string(); // Placeholder for compatibility
        }

        Ok(config)
    }
}

/// Returns the help message formatted with the program name
fn get_help(prog: &str) -> String {
    format!(
        "Usage: {} --target <target_or_file> [--max-depth <depth>] [--output <file.jsonl>] [--max-entries <limit>] [--debug] [--share-enum] [--shares <file>]\n\n\
        Arguments:\n\
        --target <target_or_file> Target hostname or file containing hostnames (one per line)\n\
        --max-depth <depth>       Maximum directory depth to traverse (default: 3)\n\
        --output <file.jsonl>     Output file path (default: indexed_shares.jsonl)\n\
        --max-entries <limit>     Maximum entries per share (optional)\n\
        --debug                   Enable debug output\n\
        --share-enum              Only enumerate shares, don't walk directories\n\
        --shares <file>           File containing UNC paths to walk (one per line)\n\
        --help                    Show this help message",
        prog
    )
}

//========================================================================
// DATA MODELS
//========================================================================

/// File metadata to be serialized line-by-line (NDJSON).
#[derive(Debug, Serialize)]
struct FileMetadata {
    name: String,
    full_path: String,
    size: Option<u64>,
    extension: Option<String>,
    created: Option<String>,
    modified: Option<String>,
    acls: Option<Vec<AceInfo>>,
    entry_type: String,  // "file", "directory", or "share"
}

/// Info on each ACE in the DACL.
#[derive(Debug, Serialize)]
struct AceInfo {
    identity: String,         // SID string (S-1-5-...)
    ace_type: String,         // "ALLOWED" or "DENIED"
    access_mask: u32,         // raw mask
    permissions: Vec<String>, // e.g. ["FullControl", "Modify", "GenericRead"]
}

//========================================================================
// SHARE ENUMERATION FUNCTIONS
//========================================================================

/// Enumerate shares on a given server/host (e.g. "MYHOST"), returning share names
/// like ["C$", "Public", "IPC$", etc.].
fn enumerate_shares(host_name: &str) -> WinResult<Vec<String>> {
    let mut buf_ptr: *mut u8 = null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    let host_wide = string_to_wide(host_name);

    let status = unsafe {
        NetShareEnum(
            PCWSTR(host_wide.as_ptr()),
            0,  // Use level 0 for SHARE_INFO_0 (just share names)
            &mut buf_ptr,
            32768,
            &mut entries_read,
            &mut total_entries,
            None,
        )
    };

    if status != 0 {
        return Err(windows::core::Error::from_win32());
    }

    let mut shares = Vec::new();
    if !buf_ptr.is_null() && entries_read > 0 {
        let share_array =
            unsafe { slice::from_raw_parts(buf_ptr as *const SHARE_INFO_0, entries_read as usize) };
        for share_info in share_array {
            let share_name = wide_str_to_string(share_info.shi0_netname.0 as *const u16);
            if !share_name.is_empty() {
                shares.push(share_name);
            }
        }
    }

    unsafe {
        if !buf_ptr.is_null() {
            NetApiBufferFree(Some(buf_ptr as *const std::ffi::c_void));
        }
    }

    Ok(shares)
}

/// Load hosts from a file or return a single host if the input is not a file path
fn load_hosts(target_or_file: &str) -> Vec<String> {
    if std::path::Path::new(target_or_file).exists() {
        // It's a file: read hostnames line by line
        match std::fs::File::open(target_or_file) {
            Ok(f) => BufReader::new(f)
                .lines()
                .filter_map(|l| l.ok())
                .filter(|line| !line.trim().is_empty())
                .collect(),
            Err(_) => {
                eprintln!("Could not open hosts file: {}", target_or_file);
                Vec::new()
            }
        }
    } else {
        // It's a single hostname
        vec![target_or_file.to_string()]
    }
}

/// Load UNC paths from a file
fn load_shares_from_file(shares_file: &str) -> Vec<String> {
    match std::fs::File::open(shares_file) {
        Ok(f) => BufReader::new(f)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|line| !line.trim().is_empty())
            .collect(),
        Err(_) => {
            eprintln!("Could not open shares file: {}", shares_file);
            Vec::new()
        }
    }
}

/// Create a BufWriter for output file
fn create_output_writer(output_path: &str) -> Result<BufWriter<std::fs::File>, std::io::Error> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;
    
    Ok(BufWriter::new(file))
}

/// Should a share be skipped (common admin shares)
fn should_skip_share(share: &str) -> bool {
    let lower = share.to_lowercase();
    lower == "admin$" || lower == "ipc$" || lower == "print$"
}

//========================================================================
// PROGRESS BAR FUNCTIONS
//========================================================================

/// Renders a progress bar to the console
fn render_progress_bar(current: usize, total: usize, width: usize) {
    let progress = if total > 0 { current as f32 / total as f32 } else { 0.0 };
    let filled_width = (progress * width as f32) as usize;
    
    // Ensure we don't exceed the width
    let filled_width = filled_width.min(width);
    
    // Create the progress bar string
    let bar: String = "[".to_string() + 
        &"#".repeat(filled_width) + 
        &" ".repeat(width - filled_width) + 
        &"]";
    
    // Create the counter display
    let counter = format!(" {}/{}", current, total);
    
    // Print the progress bar, overwriting the previous line
    print!("\r{}{}", bar, counter);
    io::stdout().flush().unwrap();
}

/// Clears the progress bar and moves to the next line
fn finish_progress_bar() {
    println!(); // Move to the next line after progress is complete
}

//========================================================================
// FILE/SHARE WALKING FUNCTIONS
//========================================================================

/// Recursively walk a UNC path up to `max_depth`. For each file/folder found,
/// retrieve metadata/ACLs and write them to NDJSON (one record per line).
fn walk_share_unc(
    unc_path: &str,
    current_depth: usize,
    max_depth: usize,
    max_entries: Option<usize>,
    writer: &mut BufWriter<std::fs::File>,
    debug_mode: bool,
) -> usize {
    // Keep track of total entries processed
    let mut entries_count = 0;

    // Initialize progress bar if this is the root level
    let total_entries = max_entries.unwrap_or(0);
    let progress_width = 50; // Width of the progress bar in characters
    
    if current_depth == 0 {
        // Initial render of the progress bar at 0
        if let Some(_) = max_entries {
            print!("Walking share {}: ", unc_path);
            render_progress_bar(0, total_entries, progress_width);
        }
    }

    // First, create an entry for the share root if this is the first level
    if current_depth == 0 {
        entries_count += process_share_root(unc_path, writer, debug_mode);
        
        // Update progress after processing the share root
        if let Some(_) = max_entries {
            render_progress_bar(entries_count, total_entries, progress_width);
        }
    }

    if current_depth > max_depth {
        // Finish progress bar when reaching max depth at root level
        if current_depth == 0 && max_entries.is_some() {
            finish_progress_bar();
        }
        return entries_count;
    }

    // Check if we've reached the max entries limit
    if let Some(limit) = max_entries {
        if entries_count >= limit {
            if debug_mode {
                println!("Reached max entries limit ({}) for share: {}", limit, unc_path);
            }
            if current_depth == 0 {
                finish_progress_bar(); // Ensure we finish the progress display
            }
            return entries_count;
        }
    }

    let path = PathBuf::from(unc_path);
    let entries = match fs::read_dir(&path) {
        Ok(e) => e,
        Err(_) => {
            // Permission denied or not a directory, skip
            if current_depth == 0 && max_entries.is_some() {
                finish_progress_bar();
            }
            return entries_count;
        }
    };

    for entry_result in entries {
        // Check if we've reached the max entries limit
        if let Some(limit) = max_entries {
            if entries_count >= limit {
                if debug_mode {
                    println!("Reached max entries limit ({}) for share: {}", limit, unc_path);
                }
                if current_depth == 0 {
                    finish_progress_bar(); // Ensure we finish the progress display
                }
                return entries_count;
            }
        }
        
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };
        let entry_path = entry.path();

        // Process this entry
        entries_count += process_filesystem_entry(&entry, writer, debug_mode);
        
        // Update progress bar if at root level
        if current_depth == 0 && max_entries.is_some() {
            render_progress_bar(entries_count, total_entries, progress_width);
        }

        // Recurse if directory
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            let full_path = entry_path.to_string_lossy().to_string();
            let remaining_entries = max_entries.map(|limit| limit.saturating_sub(entries_count));
            let sub_entries = walk_share_unc(&full_path, current_depth + 1, max_depth, remaining_entries, writer, debug_mode);
            entries_count += sub_entries;
            
            // Update progress bar after recursion if at root level
            if current_depth == 0 && max_entries.is_some() {
                render_progress_bar(entries_count, total_entries, progress_width);
            }
            
            // Check again after recursion
            if let Some(limit) = max_entries {
                if entries_count >= limit {
                    if debug_mode {
                        println!("Reached max entries limit ({}) after recursion for: {}", limit, full_path);
                    }
                    if current_depth == 0 {
                        finish_progress_bar(); // Ensure we finish the progress display
                    }
                    return entries_count;
                }
            }
        }
    }
    
    // Ensure we finish the progress display if we're at the root level
    // without filling the bar to 100% if we found fewer entries than max_entries
    if current_depth == 0 && max_entries.is_some() {
        // Just move to next line without changing the progress
        finish_progress_bar();
    }
    
    entries_count
}

/// Process a share root and create an entry for it
fn process_share_root(unc_path: &str, writer: &mut BufWriter<std::fs::File>, debug_mode: bool) -> usize {
    // Get share metadata
    let path = PathBuf::from(unc_path);
    match fs::metadata(&path) {
        Ok(metadata) => {
            let created_str = metadata.created().ok().and_then(system_time_to_string);
            let modified_str = metadata.modified().ok().and_then(system_time_to_string);
            
            // Attempt to fetch ACL info
            let acls = match get_acl_info(&path, debug_mode) {
                Ok(a) => Some(a),
                Err(_) => None,
            };

            // Create share root entry
            let share_meta = FileMetadata {
                name: unc_path.to_string(),
                full_path: unc_path.to_string(),
                size: None, // Shares don't have a meaningful size
                extension: None,
                created: created_str,
                modified: modified_str,
                acls,
                entry_type: "share".to_string(),
            };

            if let Err(e) = write_json_line(&share_meta, writer) {
                if debug_mode {
                    eprintln!("Failed to write share record for {}: {:?}", unc_path, e);
                }
            }
            
            1 // Return 1 for the entry created
        },
        Err(_) => 0 // Return 0 if we couldn't get metadata
    }
}

/// Process a filesystem entry (file or directory) and create an entry for it
fn process_filesystem_entry(
    entry: &fs::DirEntry, 
    writer: &mut BufWriter<std::fs::File>, 
    debug_mode: bool
) -> usize {
    let file_name = entry.file_name().to_string_lossy().to_string();
    let metadata = match entry.metadata() {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let entry_path = entry.path();
    let full_path = entry_path.to_string_lossy().to_string();
    let extension = entry_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(String::from);

    // Times
    let created_str = metadata.created().ok().and_then(system_time_to_string);
    let modified_str = metadata.modified().ok().and_then(system_time_to_string);

    // Attempt to fetch ACL info
    let acls = match get_acl_info(&entry_path, debug_mode) {
        Ok(a) => Some(a),
        Err(_) => None,
    };

    // Build a record
    let file_meta = FileMetadata {
        name: file_name,
        full_path: full_path.clone(),
        size: Some(metadata.len()),
        extension,
        created: created_str,
        modified: modified_str,
        acls,
        entry_type: if metadata.is_dir() {
            "directory".to_string()
        } else {
            "file".to_string()
        },
    };

    // Write NDJSON
    if let Err(e) = write_json_line(&file_meta, writer) {
        if debug_mode {
            eprintln!("Failed to write JSON record for {}: {:?}", full_path, e);
        }
    }
    
    1 // Return 1 for the entry created
}

//========================================================================
// ACL HANDLING FUNCTIONS
//========================================================================

/// Retrieve a parsed list of ACEs from a file/directory path.
/// Includes bitmask translation to common perms (FullControl, Modify, etc.).
fn get_acl_info(path: &PathBuf, debug_mode: bool) -> WinResult<Vec<AceInfo>> {
    if debug_mode {
        println!("Getting ACL info for: {}", path.display());
    }
    let wide_path = string_to_wide(&path.to_string_lossy());

    let sec_info: u32 = OWNER_SECURITY_INFORMATION.0
        | GROUP_SECURITY_INFORMATION.0
        | DACL_SECURITY_INFORMATION.0;

    // First call to get required buffer size
    let mut buf_size = 0u32;
    let first_call = unsafe {
        GetFileSecurityW(
            PCWSTR(wide_path.as_ptr()),
            sec_info,
            None,
            0,
            &mut buf_size,
        )
    };

    // We expect this call to fail with ERROR_INSUFFICIENT_BUFFER
    if first_call.as_bool() {
        if debug_mode {
            println!("Unexpected success with no buffer for {}", path.display());
        }
        return Ok(Vec::new());
    }

    // Add some padding to the buffer size to handle dynamic security descriptors
    buf_size += 1024;

    if debug_mode {
        println!("Allocating buffer of size {} for security descriptor", buf_size);
    }

    // Allocate buffer and make second call
    let mut sd_buffer = vec![0u8; buf_size as usize];
    let second_call = unsafe {
        GetFileSecurityW(
            PCWSTR(wide_path.as_ptr()),
            sec_info,
            Some(PSECURITY_DESCRIPTOR(sd_buffer.as_mut_ptr() as *mut std::ffi::c_void)),
            buf_size,
            &mut buf_size,
        )
    };

    if !second_call.as_bool() {
        let error = windows::core::Error::from_win32();
        if debug_mode {
            println!("Failed to get security descriptor for {}: {:?}", path.display(), error);
        }
        return Ok(Vec::new());
    }

    if debug_mode {
        println!("Successfully got security descriptor");
    }

    let p_sd = PSECURITY_DESCRIPTOR(sd_buffer.as_ptr() as *mut std::ffi::c_void);

    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut p_dacl = null_mut();

    let get_dacl_result = unsafe {
        GetSecurityDescriptorDacl(
            p_sd,
            &mut dacl_present as *mut i32 as *mut _,
            &mut p_dacl,
            &mut dacl_defaulted as *mut i32 as *mut _,
        )
    };

    if get_dacl_result.is_err() {
        if debug_mode {
            println!("Failed to get DACL for {}: {:?}", path.display(), windows::core::Error::from_win32());
        }
        return Ok(Vec::new());
    }

    // Check if the DACL is present
    if dacl_present == 0 || p_dacl.is_null() {
        if debug_mode {
            println!("No DACL present for {}", path.display());
        }
        return Ok(Vec::new());
    }

    if debug_mode {
        println!("DACL present, processing ACEs");
    }

    // p_dacl is an ACL pointer. We'll read its AceCount field:
    let acl_ref = unsafe { &*(p_dacl as *const windows::Win32::Security::ACL) };
    let ace_count = acl_ref.AceCount;
    let mut ace_infos = Vec::with_capacity(ace_count as usize);

    if debug_mode {
        println!("Found {} ACEs to process", ace_count);
    }

    for i in 0..ace_count {
        let mut p_ace: *mut std::ffi::c_void = null_mut();
        let get_ace_res = unsafe { GetAce(p_dacl, i as u32, &mut p_ace) };
        if get_ace_res.is_err() || p_ace.is_null() {
            if debug_mode {
                println!("Failed to get ACE {} for {}: {:?}", i, path.display(), windows::core::Error::from_win32());
            }
            continue;
        }

        let ace_header = unsafe { &*(p_ace as *const ACE_HEADER) };
        if debug_mode {
            println!("Processing ACE {} of type {}", i, ace_header.AceType);
        }

        match ace_header.AceType {
            // ACCESS_ALLOWED_ACE_TYPE = 0x00
            0x00 => {
                let allowed_ace = unsafe { &*(p_ace as *const ACCESS_ALLOWED_ACE) };
                let mask = allowed_ace.Mask;
                let sid_ptr = PSID(&allowed_ace.SidStart as *const _ as *mut std::ffi::c_void);
                
                // Just directly convert SID to string with no translation
                let sid_string = sid_to_string_sid(sid_ptr).unwrap_or_else(|| "<INVALID SID>".to_string());
                
                let permissions = parse_access_mask(mask);
                ace_infos.push(AceInfo {
                    identity: sid_string,
                    ace_type: "ALLOWED".to_string(),
                    access_mask: mask,
                    permissions,
                });
            }
            // ACCESS_DENIED_ACE_TYPE = 0x01
            0x01 => {
                let denied_ace = unsafe { &*(p_ace as *const ACCESS_DENIED_ACE) };
                let mask = denied_ace.Mask;
                let sid_ptr = PSID(&denied_ace.SidStart as *const _ as *mut std::ffi::c_void);
                
                // Just directly convert SID to string with no translation
                let sid_string = sid_to_string_sid(sid_ptr).unwrap_or_else(|| "<INVALID SID>".to_string());
                
                let permissions = parse_access_mask(mask);
                ace_infos.push(AceInfo {
                    identity: sid_string,
                    ace_type: "DENIED".to_string(),
                    access_mask: mask,
                    permissions,
                });
            }
            _ => {
                if debug_mode {
                    println!("Skipping ACE type {}", ace_header.AceType);
                }
            }
        }
    }

    if debug_mode {
        println!("Finished processing ACL for {}", path.display());
    }
    Ok(ace_infos)
}

/// Parse the raw ACE mask bits into friendly strings ("FullControl", "Modify", etc.).
fn parse_access_mask(mask: u32) -> Vec<String> {
    static SIMPLE_PERMISSIONS: &[(u32, &str)] = &[
        (0x1f01ff, "FullControl"),
        (0x0301bf, "Modify"),
        (0x0200a9, "ReadAndExecute"),
        (0x02019f, "ReadAndWrite"),
        (0x020089, "Read"),
        (0x000116, "Write"),
    ];

    // 1) Check exact matches first
    for (bits, name) in SIMPLE_PERMISSIONS {
        if mask == *bits {
            return vec![name.to_string()];
        }
    }

    // 2) Otherwise, check individual bits
    static ACCESS_MASK_BITS: &[(u32, &str)] = &[
        (0x80000000, "GenericRead"),
        (0x40000000, "GenericWrite"),
        (0x20000000, "GenericExecute"),
        (0x10000000, "GenericAll"),
        (0x02000000, "MaximumAllowed"),
        (0x01000000, "AccessSystemSecurity"),
        (0x00100000, "Synchronize"),
        (0x00080000, "WriteOwner"),
        (0x00040000, "WriteDAC"),
        (0x00020000, "ReadControl"),
        (0x00010000, "Delete"),
        (0x00000100, "WriteAttributes"),
        (0x00000080, "ReadAttributes"),
        (0x00000040, "DeleteChild"),
        (0x00000020, "Execute/Traverse"),
        (0x00000010, "WriteExtendedAttributes"),
        (0x00000008, "ReadExtendedAttributes"),
        (0x00000004, "AppendData/AddSubdirectory"),
        (0x00000002, "WriteData/AddFile"),
        (0x00000001, "ReadData/ListDirectory"),
    ];

    let mut perms = Vec::new();
    for (bit, desc) in ACCESS_MASK_BITS {
        if (mask & bit) != 0 {
            perms.push(desc.to_string());
        }
    }
    perms
}

//========================================================================
// UTILITY FUNCTIONS
//========================================================================

/// Write one record as JSON (one line) and flush.
fn write_json_line<T: Serialize>(
    record: &T,
    writer: &mut BufWriter<std::fs::File>,
) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Convert the binary SID to "S-1-5-XX" form using ConvertSidToStringSidW.
fn sid_to_string_sid(sid: PSID) -> Option<String> {
    if sid.0.is_null() {
        return None;
    }

    let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
    let success = unsafe { ConvertSidToStringSidW(sid, &mut sid_str_ptr) };
    if success == 0 || sid_str_ptr.is_null() {
        return None;
    }

    let s = wide_str_to_string(sid_str_ptr);
    unsafe {
        LocalFree(sid_str_ptr as isize);
    }

    Some(s)
}

/// Convert a SystemTime to a human-readable string (UTC).
fn system_time_to_string(time: SystemTime) -> Option<String> {
    let datetime: chrono::DateTime<chrono::Utc> = time.into();
    Some(datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Convert `&str` to wide string, null-terminated.
fn string_to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert a wide pointer to a Rust `String`.
fn wide_str_to_string(wide_ptr: *const u16) -> String {
    if wide_ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *wide_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = slice::from_raw_parts(wide_ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// Display program banner
fn display_banner() {
    println!("
  _________.__                         .___            .___             
 /   _____/|  |__ _____ _______   ____ |   | ____    __| _/____ ___  ___
 \\_____  \\ |  |  \\\\__  \\\\_  __ \\_/ __ \\|   |/    \\  / __ |/ __ \\\\  \\/  /
 /        \\|   Y  \\/ __ \\|  | \\/\\  ___/|   |   |  \\/ /_/ \\  ___/ >    < 
/_______  /|___|  (____  /__|    \\___  >___|___|  /\\____ |\\___  >__/\\_ \\
        \\/      \\/     \\/            \\/         \\/      \\/    \\/      \\/
");
    println!("Author: M.Rauch \n");
}

//========================================================================
// MODE HANDLING FUNCTIONS
//========================================================================

/// Execute in share enumeration only mode
fn run_share_enum_only_mode(config: &Config, hosts: Vec<String>) -> std::io::Result<()> {
    println!("Mode: Share enumeration only");
    println!("Output file: {}", config.output_path);
    if config.debug_mode {
        println!("Debug mode enabled");
    }
    
    // Open text file in write mode
    let mut writer = create_output_writer(&config.output_path)?;
    
    // Process hosts for share enumeration only
    for host in hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        println!("--- Enumerating shares on host: {} ---", host);
        match enumerate_shares(host) {
            Ok(shares) => {
                for share in shares {
                    // Skip standard admin shares
                    if should_skip_share(&share) {
                        if config.debug_mode {
                            println!("Skipping share: {}", share);
                        }
                        continue;
                    }

                    // Write full UNC path to file
                    let unc = format!(r"\\{}\{}", host, share);
                    if let Err(e) = writeln!(writer, "{}", unc) {
                        if config.debug_mode {
                            eprintln!("Failed to write share path {}: {:?}", unc, e);
                        }
                    } else {
                        println!("[+] Found share: {}", unc);
                    }
                }
            }
            Err(e) => {
                if config.debug_mode {
                    eprintln!("Failed to enumerate shares on {}: {:?}", host, e);
                } else {
                    println!("Host {} unreachable", host);
                }
            }
        }
    }
    
    // Final flush
    writer.flush()?;
    println!("\nDone! Share enumeration written to {}", config.output_path);
    Ok(())
}

/// Execute normal mode with file/directory indexing
fn run_normal_mode(config: &Config, hosts: Vec<String>, shares_to_walk: Vec<String>) -> std::io::Result<()> {
    println!("Max depth: {}", config.max_depth);
    println!("Output NDJSON: {}", config.output_path);
    if let Some(limit) = config.max_entries {
        println!("Max entries per share: {}", limit);
    }
    if config.debug_mode {
        println!("Debug mode enabled");
    }
    
    // Open NDJSON file in write mode
    let mut writer = create_output_writer(&config.output_path)?;

    // Process shares based on mode
    if !shares_to_walk.is_empty() {
        // --shares mode: walk pre-defined shares
        println!("Mode: Walking pre-defined shares");
        for unc_path in shares_to_walk {
            let unc_path = unc_path.trim();
            if unc_path.is_empty() {
                continue;
            }
            println!("[+] Walking share: {}", unc_path);
            walk_share_unc(&unc_path, 0, config.max_depth, config.max_entries, &mut writer, config.debug_mode);
            writer.flush()?;
        }
    } else {
        // Normal mode: enumerate shares from hosts
        for host in hosts {
            let host = host.trim();
            if host.is_empty() {
                continue;
            }
            println!("--- Enumerating shares on host: {} ---", host);
            match enumerate_shares(host) {
                Ok(shares) => {
                    for share in shares {
                        // Skip standard admin shares
                        if should_skip_share(&share) {
                            if config.debug_mode {
                                println!("Skipping share: {}", share);
                            }
                            continue;
                        }

                        // UNC path
                        let unc = format!(r"\\{}\{}", host, share);
                        println!("[+] Walking share: {}", unc);
                        walk_share_unc(&unc, 0, config.max_depth, config.max_entries, &mut writer, config.debug_mode);
                        writer.flush()?;
                    }
                }
                Err(e) => {
                    if config.debug_mode {
                        eprintln!("Failed to enumerate shares on {}: {:?}", host, e);
                    } else {
                        println!("Host {} unreachable", host);
                    }
                }
            }
        }
    }

    // Final flush
    writer.flush()?;
    println!("\nDone! File enumeration written to {}", config.output_path);
    Ok(())
}

//========================================================================
// MAIN PROGRAM
//========================================================================

fn main() {
    // Parse command line arguments
    let config = match Config::from_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // Display ASCII art banner
    display_banner();

    // Handle different input modes
    let (hosts, shares_to_walk) = if let Some(shares_file) = &config.shares_file {
        // --shares mode: read UNC paths directly from file
        let shares = load_shares_from_file(shares_file);
        
        if config.debug_mode {
            println!("Loaded {} shares from file: {}", shares.len(), shares_file);
        }
        
        (Vec::new(), shares) // No hosts needed in this mode
    } else {
        // Normal mode: gather hosts from the given argument
        let hosts = load_hosts(&config.target_or_file);
        (hosts, Vec::new()) // No pre-defined shares in this mode
    };

    if config.shares_file.is_some() {
        println!("Shares to walk: {}", shares_to_walk.len());
    } else {
        println!("Hosts to enumerate: {}", hosts.len());
    }
    
    // Run in the appropriate mode
    let result = if config.share_enum_only {
        run_share_enum_only_mode(&config, hosts)
    } else {
        run_normal_mode(&config, hosts, shares_to_walk)
    };

    // Handle any errors from the execution
    if let Err(e) = result {
        eprintln!("Error during execution: {}", e);
        process::exit(1);
    }
}
