use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, LdapError};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use serde::Serialize;
use serde_json::to_writer;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use chrono::{DateTime, Utc};

#[derive(Debug)]
enum EnumError {
    Ldap(LdapError),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl From<LdapError> for EnumError {
    fn from(error: LdapError) -> Self {
        EnumError::Ldap(error)
    }
}

impl From<serde_json::Error> for EnumError {
    fn from(error: serde_json::Error) -> Self {
        EnumError::Json(error)
    }
}

impl From<std::io::Error> for EnumError {
    fn from(error: std::io::Error) -> Self {
        EnumError::Io(error)
    }
}

#[derive(Debug, Serialize)]
struct ComputerAccount {
    distinguished_name: String,
    cn: String,
    dns_hostname: Option<String>,
    operating_system: Option<String>,
    os_version: Option<String>,
    when_created: Option<String>,
    last_logon: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserAccount {
    distinguished_name: String,
    cn: String,
    sam_account_name: Option<String>,
    sid: Option<String>,
    when_created: Option<String>,
    last_logon: Option<String>,
}

#[derive(Debug, Serialize)]
struct Group {
    distinguished_name: String,
    cn: String,
    sid: Option<String>,
    members: Vec<String>,
}

fn filetime_to_datetime(filetime: &str) -> Option<String> {
    filetime.parse::<i64>().ok().and_then(|ft| {
        if ft == 0 {
            None
        } else {
            let seconds_since_windows_epoch = ft / 10_000_000;
            let unix_epoch = seconds_since_windows_epoch - 11644473600;
            let datetime = DateTime::<Utc>::from_timestamp(unix_epoch, 0)?;
            Some(datetime.to_rfc3339())
        }
    })
}

// Parse a Windows SID from binary form to string representation (e.g., "S-1-5-21-...")
fn parse_sid(sid_bytes: &[u8]) -> Option<String> {
    if sid_bytes.len() < 8 {
        return None; // SID too short
    }

    let revision = sid_bytes[0];
    let sub_authority_count = sid_bytes[1] as usize;
    
    if sid_bytes.len() < 8 + (sub_authority_count * 4) {
        return None; // SID data incomplete
    }
    
    // Authority is a 48-bit value stored in big-endian
    let authority = ((sid_bytes[2] as u64) << 40) |
                   ((sid_bytes[3] as u64) << 32) |
                   ((sid_bytes[4] as u64) << 24) |
                   ((sid_bytes[5] as u64) << 16) |
                   ((sid_bytes[6] as u64) << 8) |
                    (sid_bytes[7] as u64);
    
    let mut result = format!("S-{}-{}", revision, authority);
    
    // Sub-authorities are stored in little-endian
    for i in 0..sub_authority_count {
        let offset = 8 + (i * 4);
        let sub_authority = 
            ((sid_bytes[offset] as u32)) |
            ((sid_bytes[offset + 1] as u32) << 8) |
            ((sid_bytes[offset + 2] as u32) << 16) |
            ((sid_bytes[offset + 3] as u32) << 24);
        
        result.push_str(&format!("-{}", sub_authority));
    }
    
    Some(result)
}

async fn ldap_search(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    filter: &str,
    attrs: Vec<&str>,
) -> ldap3::result::Result<Vec<SearchEntry>> {
    println!("Searching with filter: {}", filter);
    
    // Use paged search with adapter chain
    let adapters: Vec<Box<dyn Adapter<'_, &str, Vec<&str>>>> = vec![
        Box::new(PagedResults::new(1000)), // AD default MaxPageSize is 1000
        Box::new(EntriesOnly::new()),
    ];

    let mut stream = ldap
        .streaming_search_with(
            adapters,
            base_dn,
            Scope::Subtree,
            filter,
            attrs,
        )
        .await?;

    let mut entries = Vec::new();
    
    // Iterate through all pages and entries
    while let Some(re) = stream.next().await? {
        // Safe: EntriesOnly ensures `re` is a real SearchResultEntry.
        let se = SearchEntry::construct(re);
        entries.push(se);
    }

    // Ensure the overall search completed successfully
    stream.finish().await.success()?;
    
    println!("Retrieved {} entries", entries.len());
    
    Ok(entries)
}

async fn enumerate_computers(ldap: &mut ldap3::Ldap, base_dn: &str) -> Result<(), EnumError> {
    let entries = ldap_search(ldap, base_dn, "(objectClass=computer)", vec![
        "distinguishedName", "cn", "dNSHostName", "operatingSystem",
        "operatingSystemVersion", "whenCreated", "lastLogonTimestamp"]).await?;

    let file = File::create("computers_.jsonl")?;
    let mut writer = BufWriter::new(file);

    for entry in entries {
        let computer = ComputerAccount {
            distinguished_name: entry.attrs.get("distinguishedName").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            cn: entry.attrs.get("cn").and_then(|v| v.get(0)).cloned().unwrap_or_default(),
            dns_hostname: entry.attrs.get("dNSHostName").and_then(|v| v.get(0)).cloned(),
            operating_system: entry.attrs.get("operatingSystem").and_then(|v| v.get(0)).cloned(),
            os_version: entry.attrs.get("operatingSystemVersion").and_then(|v| v.get(0)).cloned(),
            when_created: entry.attrs.get("whenCreated").and_then(|v| v.get(0)).cloned(),
            last_logon: entry.attrs.get("lastLogonTimestamp").and_then(|v| v.get(0)).and_then(|val| filetime_to_datetime(val)),
        };
        to_writer(&mut writer, &computer)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn get_string_attr(entry: &SearchEntry, attr_name: &str) -> Option<String> {
    entry.attrs.get(attr_name).and_then(|v| v.get(0)).cloned()
}

// Returns well-known SIDs for built-in groups
fn get_well_known_sid(group_name: &str) -> Option<String> {
    match group_name {
        "Administrators" => Some("S-1-5-32-544".to_string()),
        "Users" => Some("S-1-5-32-545".to_string()),
        "Guests" => Some("S-1-5-32-546".to_string()),
        "Power Users" => Some("S-1-5-32-547".to_string()),
        "Account Operators" => Some("S-1-5-32-548".to_string()),
        "Server Operators" => Some("S-1-5-32-549".to_string()),
        "Print Operators" => Some("S-1-5-32-550".to_string()),
        "Backup Operators" => Some("S-1-5-32-551".to_string()),
        "Replicators" => Some("S-1-5-32-552".to_string()),
        "Replicator" => Some("S-1-5-32-552".to_string()), // For backwards compatibility
        "Pre-Windows 2000 Compatible Access" => Some("S-1-5-32-554".to_string()),
        "Remote Desktop Users" => Some("S-1-5-32-555".to_string()),
        "Network Configuration Operators" => Some("S-1-5-32-556".to_string()),
        "Incoming Forest Trust Builders" => Some("S-1-5-32-557".to_string()),
        "Performance Monitor Users" => Some("S-1-5-32-558".to_string()),
        "Performance Log Users" => Some("S-1-5-32-559".to_string()),
        "Windows Authorization Access Group" => Some("S-1-5-32-560".to_string()),
        "Terminal Server License Servers" => Some("S-1-5-32-561".to_string()),
        "Distributed COM Users" => Some("S-1-5-32-562".to_string()),
        "IIS_IUSRS" => Some("S-1-5-32-568".to_string()),
        "Cryptographic Operators" => Some("S-1-5-32-569".to_string()),
        "Event Log Readers" => Some("S-1-5-32-573".to_string()),
        "Certificate Service DCOM Access" => Some("S-1-5-32-574".to_string()),
        "RDS Remote Access Servers" => Some("S-1-5-32-575".to_string()),
        "RDS Endpoint Servers" => Some("S-1-5-32-576".to_string()),
        "RDS Management Servers" => Some("S-1-5-32-577".to_string()),
        "Hyper-V Administrators" => Some("S-1-5-32-578".to_string()),
        "Access Control Assistance Operators" => Some("S-1-5-32-579".to_string()),
        "Remote Management Users" => Some("S-1-5-32-580".to_string()),
        _ => None,
    }
}

fn get_sid_attr(entry: &SearchEntry, attr_name: &str) -> Option<String> {
    // Try to get SID from binary attribute
    if let Some(vals) = entry.bin_attrs.get(attr_name) {
        if let Some(bytes) = vals.get(0) {
            return parse_sid(bytes);
        }
    }
    
    // If it's a built-in group, fall back to well-known SIDs
    if entry.dn.contains("CN=Builtin,") {
        let cn = get_string_attr(entry, "cn").unwrap_or_default();
        return get_well_known_sid(&cn);
    }
    
    None
}

async fn enumerate_users(ldap: &mut ldap3::Ldap, base_dn: &str) -> Result<(), EnumError> {
    let attrs_to_request = vec![
        "distinguishedName", "cn", "sAMAccountName", "objectSid",
        "whenCreated", "lastLogonTimestamp"
    ];
    
    // Use a more specific filter that gets users but excludes computer accounts
    // objectCategory=person restricts to person objects, which includes users but not computers
    // (&(objectClass=user)(objectCategory=person)(!objectClass=computer))
    let filter = "(&(objectClass=user)(objectCategory=person))";
    
    let entries = ldap_search(ldap, base_dn, filter, attrs_to_request).await?;

    let file = File::create("users_.jsonl")?;
    let mut writer = BufWriter::new(file);

    for entry in entries {
        let user = UserAccount {
            distinguished_name: get_string_attr(&entry, "distinguishedName").unwrap_or_default(),
            cn: get_string_attr(&entry, "cn").unwrap_or_default(),
            sam_account_name: get_string_attr(&entry, "sAMAccountName"),
            sid: get_sid_attr(&entry, "objectSid"),
            when_created: get_string_attr(&entry, "whenCreated"),
            last_logon: entry.attrs.get("lastLogonTimestamp")
                         .and_then(|v| v.get(0))
                         .and_then(|val| filetime_to_datetime(val)),
        };
        to_writer(&mut writer, &user)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

async fn enumerate_groups(ldap: &mut ldap3::Ldap, base_dn: &str) -> Result<(), EnumError> {
    let entries = ldap_search(ldap, base_dn, "(objectClass=group)", vec![
        "distinguishedName", "cn", "member", "objectSid"]).await?;

    let file = File::create("groups_.jsonl")?;
    let mut writer = BufWriter::new(file);

    for entry in entries {
        let cn = get_string_attr(&entry, "cn").unwrap_or_default();
        let sid = get_sid_attr(&entry, "objectSid").or_else(|| Some(cn.clone()));

        let group = Group {
            distinguished_name: get_string_attr(&entry, "distinguishedName").unwrap_or_default(),
            cn,
            sid,
            members: entry.attrs.get("member").cloned().unwrap_or_default(),
        };
        to_writer(&mut writer, &group)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn handle_enumeration_error(error: EnumError, mode: &str, base_dn: &str) -> Result<(), EnumError> {
    match &error {
        EnumError::Ldap(ldap_error) => {
            let error_str = ldap_error.to_string();
            if error_str.contains("rc:4") || error_str.contains("Size limit exceeded") {
                eprintln!("ERROR: Size limit exceeded while enumerating {}.", mode);
                eprintln!("This means the server has a hard limit that prevents returning results.");
                eprintln!();
                eprintln!("SOLUTIONS:");
                eprintln!("1. Use a more specific base DN:");
                if base_dn.starts_with("DC=") && !base_dn.contains("CN=") && !base_dn.contains("OU=") {
                    eprintln!("   Current: \"{}\" (searches entire domain)", base_dn);
                    eprintln!("   Try:     \"CN=Users,{}\" (users/groups only)", base_dn);
                    eprintln!("   Or:      \"CN=Computers,{}\" (computers only)", base_dn);
                } else {
                    eprintln!("   Use containers like CN=Users,DC=domain,DC=com instead of domain root");
                }
                eprintln!("2. Run enumeration by type instead of 'all':");
                eprintln!("   {} <dc> <base_dn> -m users", std::env::args().next().unwrap_or_default());
                eprintln!("   {} <dc> <base_dn> -m computers", std::env::args().next().unwrap_or_default());
                eprintln!("   {} <dc> <base_dn> -m groups", std::env::args().next().unwrap_or_default());
                eprintln!("3. Contact your AD administrator to increase server-side size limits");
                eprintln!();
            } else {
                eprintln!("LDAP Error during {} enumeration: {}", mode, ldap_error);
            }
        }
        EnumError::Json(json_error) => {
            eprintln!("JSON Error during {} enumeration: {}", mode, json_error);
        }
        EnumError::Io(io_error) => {
            eprintln!("I/O Error during {} enumeration: {}", mode, io_error);
        }
    }
    Err(error)
}

// Function to derive base DN from UPN format username
fn derive_base_dn_from_upn(username: &str) -> Option<String> {
    if let Some(domain_part) = username.split('@').nth(1) {
        let components: Vec<&str> = domain_part.split('.').collect();
        if components.len() >= 2 {
            let dn = components.iter()
                .map(|component| format!("DC={}", component))
                .collect::<Vec<String>>()
                .join(",");
            Some(dn)
        } else {
            None
        }
    } else {
        None
    }
}

// Function to query LDAP root DSE for default naming context
async fn get_default_naming_context(ldap: &mut ldap3::Ldap) -> Result<Option<String>, EnumError> {
    println!("Querying LDAP server for default naming context...");
    
    match ldap_search(ldap, "", "(objectClass=*)", vec!["defaultNamingContext"]).await {
        Ok(entries) => {
            if let Some(entry) = entries.first() {
                if let Some(default_nc) = entry.attrs.get("defaultNamingContext") {
                    if let Some(dn) = default_nc.first() {
                        println!("Found default naming context: {}", dn);
                        return Ok(Some(dn.clone()));
                    }
                }
            }
            println!("No default naming context found in root DSE");
            Ok(None)
        }
        Err(e) => {
            println!("Failed to query root DSE: {}", e);
            Ok(None)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), EnumError> {
    let args: Vec<String> = env::args().collect();
    let default_mode = String::from("all");
    let mut mode = &default_mode;
    let mut username = String::new();
    let mut password = String::new();
    let mut use_ldaps = false;

    let mut dc_hostname = String::new();
    let mut base_dn = "".to_string();

    let mut args_iter = args.iter().skip(1);
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-m" => mode = args_iter.next().unwrap_or(&default_mode),
            "-u" => username = args_iter.next().unwrap_or(&String::new()).to_string(),
            "-p" => password = args_iter.next().unwrap_or(&String::new()).to_string(),
            "-s" => use_ldaps = true,
            "-dn" => base_dn = args_iter.next().unwrap_or(&String::new()).to_string(),
            hostname if !hostname.starts_with('-') && dc_hostname.is_empty() => {
                dc_hostname = hostname.to_string();
            }
            _ => {}
        }
    }

    if dc_hostname.is_empty() {
        println!("Usage: {} <domain_controller> [-dn base_dn] [-m mode] [-u username] [-p password] [-s]", args[0]);
        println!("Example: {} dc01.example.com -u \"user@example.com\" -p \"password\"", args[0]);
        println!("Note: When connecting via IP address, use UPN format for username (username@DOMAIN.COM)");
        println!();
        println!("Options:");
        println!("  -dn <base_dn>: Base DN for LDAP searches (optional - auto-detected if not provided)");
        println!("  -m <mode>    : Mode of operation (computers, users, groups, or all)");
        println!("  -u <username>: Username for authentication");
        println!("  -p <password>: Password for authentication");
        println!("  -s           : Use LDAPS (LDAP over TLS/SSL) instead of standard LDAP");
        return Ok(());
    }

    // Adjust LDAPS port if not specified
    let ldap_url = if use_ldaps && !dc_hostname.contains(':') {
        format!("ldaps://{}:636", dc_hostname)
    } else if !use_ldaps && !dc_hostname.contains(':') {
        format!("ldap://{}:389", dc_hostname)
    } else {
        let protocol = if use_ldaps { "ldaps" } else { "ldap" };
        format!("{}://{}", protocol, dc_hostname)
    };

    println!("Connecting to: {}", ldap_url);
    if use_ldaps {
        println!("Using LDAPS (TLS encrypted connection)");
    } else {
        println!("Using plain LDAP (unencrypted connection)");
        println!("Warning: If the DC requires LDAP signing, use -s flag for LDAPS");
    }

    // Build connection settings with TLS certificate validation disabled
    let settings = LdapConnSettings::new()
        .set_no_tls_verify(true);

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &ldap_url).await?;
    ldap3::drive!(conn);
    
    if !username.is_empty() && !password.is_empty() {
        println!("Binding with provided credentials...");
        match ldap.simple_bind(&username, &password).await {
            Ok(result) => {
                result.success()?;
                println!("Authentication successful");
            }
            Err(e) => {
                if e.to_string().contains("integrity checking") || e.to_string().contains("signing") {
                    eprintln!("ERROR: LDAP signing is required by the server.");
                    eprintln!("SOLUTION: Use the -s flag to connect via LDAPS instead:");
                    eprintln!("  {} {} -s -u \"{}\" -p \"[password]\"", args[0], dc_hostname, username);
                    eprintln!("This error occurs when the DC has 'Domain controller: LDAP server signing requirements' set to 'Require signing'");
                }
                return Err(e.into());
            }
        }
    } else {
        println!("Attempting SASL GSSAPI bind using SPN for {}...", dc_hostname);
        match ldap.sasl_gssapi_bind(&dc_hostname).await {
            Ok(result) => {
                result.success()?;
                println!("GSSAPI authentication successful");
            }
            Err(e) => {
                if e.to_string().contains("integrity checking") || e.to_string().contains("signing") {
                    eprintln!("ERROR: LDAP signing is required by the server.");
                    eprintln!("SOLUTION: Use the -s flag to connect via LDAPS instead:");
                    eprintln!("  {} {} -s", args[0], dc_hostname);
                    eprintln!("This error occurs when the DC has 'Domain controller: LDAP server signing requirements' set to 'Require signing'");
                }
                return Err(e.into());
            }
        }
    }

    // If base_dn is not provided, try to auto-detect it
    if base_dn.is_empty() {
        println!("Base DN not provided. Attempting auto-detection...");
        
        // First try to derive from UPN username
        if !username.is_empty() {
            if let Some(upn_base_dn) = derive_base_dn_from_upn(&username) {
                base_dn = upn_base_dn;
                println!("✓ Derived base DN from username: {}", base_dn);
            }
        }
        
        // If still empty, query LDAP server for default naming context
        if base_dn.is_empty() {
            match get_default_naming_context(&mut ldap).await {
                Ok(Some(default_naming_context)) => {
                    base_dn = default_naming_context;
                    println!("✓ Found default naming context: {}", base_dn);
                }
                Ok(None) => {
                    eprintln!("✗ Could not auto-detect base DN");
                    eprintln!("Please specify a base DN using -dn option");
                    eprintln!("Example: {} {} -dn \"DC=example,DC=com\"", args[0], dc_hostname);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("Error querying for default naming context: {:?}", e);
                    eprintln!("Please specify a base DN using -dn option");
                    return Ok(());
                }
            }
        }
    } else {
        println!("Using specified base DN: {}", base_dn);
    }

    let result = match mode.as_str() {
        "computers" => enumerate_computers(&mut ldap, &base_dn).await,
        "users" => enumerate_users(&mut ldap, &base_dn).await,
        "groups" => enumerate_groups(&mut ldap, &base_dn).await,
        "all" => {
            if let Err(e) = enumerate_computers(&mut ldap, &base_dn).await {
                return handle_enumeration_error(e, "computers", &base_dn);
            }
            if let Err(e) = enumerate_users(&mut ldap, &base_dn).await {
                return handle_enumeration_error(e, "users", &base_dn);
            }
            enumerate_groups(&mut ldap, &base_dn).await
        }
        _ => {
            println!("Invalid mode specified.");
            return Ok(());
        }
    };
    
    if let Err(e) = result {
        return handle_enumeration_error(e, mode, &base_dn);
    }

    ldap.unbind().await?;
    println!("Enumeration complete.");

    Ok(())
}
