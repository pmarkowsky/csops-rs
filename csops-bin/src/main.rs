use clap::Parser;
use csops::*;
use hex;
use nix::errno::Errno;

const SHA1_DIGEST_LENGTH: usize = 20;

fn flag_set(flags: u32, flag: u32) -> bool {
    flags & flag == flag
}

pub fn decode_status(pid: i32, status: u32) {
    print!("PID: {} cs_flags: {}", pid, status);
    let flags = [
        (codesign::CS_VALID, "CS_VALID"),
        (codesign::CS_ADHOC, "CS_ADHOC"),
        (codesign::CS_GET_TASK_ALLOW, "CS_GET_TASK_ALLOW"),
        (codesign::CS_INSTALLER, "CS_INSTALLER"),
        (codesign::CS_FORCED_LV, "CS_FORCED_LV"),
        (codesign::CS_INVALID_ALLOWED, "CS_INVALID_ALLOWED"),
        (codesign::CS_HARD, "CS_HARD"),
        (codesign::CS_KILL, "CS_KILL"),
        (codesign::CS_CHECK_EXPIRATION, "CS_CHECK_EXPIRATION"),
        (codesign::CS_RESTRICT, "CS_RESTRICT"),
        (codesign::CS_ENFORCEMENT, "CS_ENFORCEMENT"),
        (codesign::CS_REQUIRE_LV, "CS_REQUIRE_LV"),
        (
            codesign::CS_ENTITLEMENTS_VALIDATED,
            "CS_ENTITLEMENTS_VALIDATED",
        ),
        (codesign::CS_NVRAM_UNRESTRICTED, "CS_NVRAM_UNRESTRICTED"),
        (codesign::CS_RUNTIME, "CS_RUNTIME"),
        (codesign::CS_LINKER_SIGNED, "CS_LINKER_SIGNED"),
        (codesign::CS_EXEC_SET_HARD, "CS_EXEC_SET_HARD"),
        (codesign::CS_EXEC_SET_KILL, "CS_EXEC_SET_KILL"),
        (codesign::CS_EXEC_SET_ENFORCEMENT, "CS_EXEC_SET_ENFORCEMENT"),
        (codesign::CS_EXEC_INHERIT_SIP, "CS_EXEC_INHERIT_SIP"),
        (codesign::CS_KILLED, "CS_KILLED"),
        (codesign::CS_NO_UNTRUSTED_HELPERS, "CS_NO_UNTRUSTED_HELPERS"),
        (codesign::CS_PLATFORM_BINARY, "CS_PLATFORM_BINARY"),
        (codesign::CS_PLATFORM_PATH, "CS_PLATFORM_PATH"),
        (codesign::CS_DEBUGGED, "CS_DEBUGGED"),
        (codesign::CS_SIGNED, "CS_SIGNED"),
        (codesign::CS_DEV_CODE, "CS_DEV_CODE"),
        (codesign::CS_DATAVAULT_CONTROLLER, "CS_DATAVAULT_CONTROLLER"),
    ];

    for (flag, output) in flags {
        if flag_set(status, flag) {
            print!("; {} ", output);
        }
    }
    println!();
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum CSOperation {
    Status,
    MarkInvalid,
    MarkHard,
    MarkKill,
    ExecutablePath,
    CDHash,
    Entitlements,
    ClearPlatform,
    ClearInstaller,
    SigningID,
    TeamID,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// csop operation
    #[arg(short, long)]
    operation: CSOperation,
    // pid
    pid: i32,
}

fn main() {
    let args = Args::parse();

    match args.operation {
        CSOperation::Status => {
            let (result, status) = csops_int(args.pid, codesign::CS_OPS_STATUS);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            } else {
                decode_status(args.pid, status);
            }
        }
        CSOperation::MarkInvalid => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_MARKINVALID);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        }
        CSOperation::MarkHard => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_MARKHARD);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        }
        CSOperation::MarkKill => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_MARKKILL);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        }
        CSOperation::ExecutablePath => {
            const PATH_SIZE: usize = 1024;
            let mut buffer: [u8; PATH_SIZE] = [0; PATH_SIZE];
            let result = csops(args.pid, codesign::CS_OPS_PIDPATH, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return;
            }
            let path = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Executable Path: {}", args.pid, path);
        }
        CSOperation::CDHash => {
            let mut buffer: [u8; SHA1_DIGEST_LENGTH] = [0; SHA1_DIGEST_LENGTH];
            let result = csops(args.pid, codesign::CS_OPS_CDHASH, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return;
            }
            let cdhash = hex::encode(buffer);
            println!("PID: {} -> CDHash: {}", args.pid, cdhash);
        }
        CSOperation::Entitlements => {
            const ENTITLEMENTS_SIZE: usize = 1024 * 1024;
            let mut buffer: [u8; ENTITLEMENTS_SIZE] = [0; ENTITLEMENTS_SIZE];
            let result = csops(args.pid, codesign::CS_OPS_ENTITLEMENTS_BLOB, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return;
            }
            let entitlements = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Entitlements: {}", args.pid, entitlements);
        }
        CSOperation::ClearPlatform => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_CLEARPLATFORM);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        }
        CSOperation::ClearInstaller => {
            let (result, _) = csops_int(args.pid, codesign::CS_OPS_CLEARINSTALLER);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
            }
        }
        CSOperation::SigningID => {
            const SIGNINGID_SIZE: usize = (1024 * 1024) as usize;
            let mut buffer: [u8; SIGNINGID_SIZE] = [0; SIGNINGID_SIZE];
            let result = csops(args.pid, codesign::CS_OPS_IDENTITY, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return;
            }
            let signingid = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> Code Signing ID: {}", args.pid, signingid);
        }
        CSOperation::TeamID => {
            const TEAMID_SIZE: usize = (codesign::CS_MAX_TEAMID_LEN - 1) as usize;
            let mut buffer: [u8; TEAMID_SIZE] = [0; TEAMID_SIZE];
            let result = csops(args.pid, codesign::CS_OPS_TEAMID, &mut buffer);
            if result < 0 {
                let errno = Errno::last();
                println!("Error: {}, {}", result, errno.desc());
                return;
            }
            let teamid = String::from_utf8(buffer.to_vec()).unwrap();
            println!("PID: {} -> TeamID: {}", args.pid, teamid);
        }
        _ => {
            println!("Invalid operation");
        }
    }
}
