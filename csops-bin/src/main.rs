use csops::*;
use clap::Parser;
use nix::errno::Errno;
use hex;

const SHA1_DIGEST_LENGTH: usize = 20;


fn flag_set(flags: u32, flag: u32) -> bool {
    flags & flag == flag
}

pub fn decode_status(pid: i32, status: u32) {
    print!("PID: {} cs_flags: {}", pid, status);
    if flag_set(status, codesign::CS_VALID) {
        print!("; CS_VALID ");
    }
    if flag_set(status, codesign::CS_ADHOC) {
        print!("; CS_ADHOC ");
    }
    if flag_set(status, codesign::CS_GET_TASK_ALLOW) {
        print!("; CS_GET_TASK_ALLOW ");
    }
    if flag_set(status, codesign::CS_INSTALLER) {
        print!("; CS_INSTALLER ");
    }
    if flag_set(status, codesign::CS_FORCED_LV) {
        print!("; CS_FORCED_LV ");
    }
    if flag_set(status, codesign::CS_INVALID_ALLOWED) {
        print!("; CS_INVALID_ALLOWED ");
    }
    if flag_set(status, codesign::CS_HARD) {
        print!("; CS_HARD ");
    }
    if flag_set(status, codesign::CS_KILL) {
        print!("; CS_KILL ");
    }
    if flag_set(status, codesign::CS_CHECK_EXPIRATION) {
        print!("; CS_CHECK_EXPIRATION ");
    }
    if flag_set(status, codesign::CS_RESTRICT) {
        print!("; CS_RESTRICT ");
    }
    if flag_set(status, codesign::CS_ENFORCEMENT) {
        print!("; CS_ENFORCEMENT ");
    }
    if flag_set(status, codesign::CS_REQUIRE_LV) {
        print!("; CS_REQUIRE_LV ");
    }
    if flag_set(status, codesign::CS_ENTITLEMENTS_VALIDATED) {
        print!("; CS_ENTITLEMENTS_VALIDATED ");
    }
    if flag_set(status, codesign::CS_NVRAM_UNRESTRICTED) {
        print!("; CS_NVRAM_UNRESTRICTED ");
    }
    if flag_set(status, codesign::CS_RUNTIME) {
        print!("; CS_RUNTIME ");
    }
    if flag_set(status, codesign::CS_LINKER_SIGNED) {
        print!("; CS_LINKER_SIGNED ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_HARD) {
        print!("; CS_EXEC_SET_HARD ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_KILL) {
        print!("; CS_EXEC_SET_KILL ");
    }
    if flag_set(status, codesign::CS_EXEC_SET_ENFORCEMENT) {
        print!("; CS_EXEC_SET_ENFORCEMENT ");
    }
    if flag_set(status, codesign::CS_EXEC_INHERIT_SIP) {
        print!("; CS_EXEC_INHERIT_SIP ");
    }
    if flag_set(status, codesign::CS_KILLED) {
        print!("; CS_KILLED ");
    }
    if flag_set(status, codesign::CS_NO_UNTRUSTED_HELPERS) {
        print!("; CS_NO_UNTRUSTED_HELPERS ");
    }
    if flag_set(status, codesign::CS_PLATFORM_BINARY) {
        print!("; CS_PLATFORM_BINARY ");
    }
    if flag_set(status, codesign::CS_PLATFORM_PATH) {
        print!("; CS_PLATFORM_PATH ");
    }
    if flag_set(status, codesign::CS_DEBUGGED) {
        print!("; CS_DEBUGGED ");
    }
    if flag_set(status, codesign::CS_SIGNED) {
        print!("; CS_SIGNED ");
    }
    if flag_set(status, codesign::CS_DEV_CODE) {
        print!("; CS_DEV_CODE ");
    }
    if flag_set(status, codesign::CS_DATAVAULT_CONTROLLER) {
        print!("; CS_DATAVAULT_CONTROLLER ");
    }
    println!();
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// csop operation
    #[arg(short, long)]
    operation: String,
    // pid
    pid: i32,
}


fn main() {
    let args = Args::parse();

    match args.operation.as_str() {
        "status" => {
            let (result, status ) = csops_int(args.pid, codesign::CS_OPS_STATUS);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            } else {
                decode_status(args.pid, status);
            }
        },
        "mark_invalid" => {
            let (result , _) = csops_int(args.pid, codesign::CS_OPS_MARKINVALID);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        },
        "mark_hard" => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_MARKHARD);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        },
        "mark_kill" => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_MARKKILL);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        },
        "executable_path" => {
            const path_size: usize = 1024;
            let mut buffer : [u8; path_size] = [0; path_size];
            let result = csops(args.pid, codesign::CS_OPS_PIDPATH, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return
            }
            let path = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Executable Path: {}", args.pid, path);
        },
        "cdhash" => {
            let mut buffer : [u8; SHA1_DIGEST_LENGTH] = [0; SHA1_DIGEST_LENGTH];
            let result = csops(args.pid, codesign::CS_OPS_CDHASH, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return
            }
            let cdhash = hex::encode(buffer);
            println!("PID: {} -> CDHash: {}", args.pid, cdhash);
        },
        "entitlements" => {
            const entitlements_size: usize = 1024 * 1024;
            let mut buffer : [u8; entitlements_size] = [0; entitlements_size];
            let result = csops(args.pid, codesign::CS_OPS_ENTITLEMENTS_BLOB, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return
            }
            let entitlements = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Entitlements: {}", args.pid, entitlements);
        },
        "clear_platform" => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_CLEARPLATFORM);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        },
        "clear_installer" => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_CLEARINSTALLER);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        },
        "signingid" => {
            const signingid_size: usize = (1024 * 1024) as usize;
            let mut buffer : [u8; signingid_size] = [0; signingid_size];
            let result = csops(args.pid, codesign::CS_OPS_IDENTITY, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return
            }
            let signingid = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Code Signing ID: {}", args.pid, signingid);
        },
        "teamid" => {
            const teamid_size: usize = (codesign::CS_MAX_TEAMID_LEN - 1) as usize;
            let mut buffer : [u8; teamid_size] = [0; teamid_size];
            let result = csops(args.pid, codesign::CS_OPS_TEAMID, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return
            }
            let teamid = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> TeamID: {}", args.pid, teamid);
        },
        _ => {
            println!("Invalid operation");
        }
    }
}
