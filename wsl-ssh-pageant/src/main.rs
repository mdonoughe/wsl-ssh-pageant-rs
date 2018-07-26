#[macro_use]
extern crate clap;
extern crate futures;
extern crate nix;
extern crate tokio;
extern crate tokio_process;
extern crate tokio_uds;

use clap::{AppSettings, Arg, ArgGroup};
use futures::future::Either;
use futures::prelude::*;
use nix::libc;
use nix::sys::signal::{self, Signal};
use nix::unistd::{self, ForkResult, Pid};
use std::borrow::Borrow;
use std::env::{self, VarError};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{io, process};
use tokio::prelude::*;
use tokio_process::CommandExt;
use tokio_uds::UnixListener;

enum Shell {
    Bourne,
    C,
}

enum BindAddress<'a> {
    Provided(&'a Path),
    Temporary(PathBuf),
}

impl<'a> AsRef<Path> for BindAddress<'a> {
    fn as_ref(&self) -> &Path {
        match self {
            BindAddress::Provided(path) => path,
            BindAddress::Temporary(path) => path.borrow(),
        }
    }
}

impl<'a> AsRef<OsStr> for BindAddress<'a> {
    fn as_ref(&self) -> &OsStr {
        let path: &Path = self.as_ref();
        path.as_ref()
    }
}

fn mkdtemp(template: PathBuf) -> Result<PathBuf, io::Error> {
    let mut template = CString::new(template.as_os_str().as_bytes())
        .unwrap()
        .into_bytes_with_nul();
    unsafe {
        let result = libc::mkdtemp(template.as_mut_ptr() as *mut i8);
        if result.is_null() {
            Err(io::Error::last_os_error())
        } else {
            template.pop();
            Ok(PathBuf::from(OsString::from_vec(
                CString::new(template).unwrap().into_bytes(),
            )))
        }
    }
}

fn write_shell<A: AsRef<OsStr>>(
    shell: Shell,
    bind_address: &A,
    child: Pid,
) -> Result<(), io::Error> {
    let out = io::stdout();
    let mut out = out.lock();
    match shell {
        Shell::Bourne => {
            write!(out, "SSH_AUTH_SOCK=")?;
            out.write_all(bind_address.as_ref().as_bytes())?;
            write!(out, "; export SSH_AUTH_SOCK;\n")?;
            write!(out, "SSH_AGENT_PID={}; export SSH_AGENT_PID;\n", child)?;
        }
        Shell::C => {
            write!(out, "setenv SSH_AUTH_SOCK ")?;
            out.write_all(bind_address.as_ref().as_bytes())?;
            write!(out, ";\n")?;
            write!(out, "setenv SSH_AGENT_PID {}\n", child)?;
        }
    }
    write!(out, "echo agent is process {}\n", child)?;
    out.flush()?;
    Ok(())
}

fn main() {
    let matches = app_from_crate!()
        .setting(AppSettings::TrailingVarArg)
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(
            Arg::with_name("BIND_ADDRESS")
                .short("a")
                .takes_value(true)
                .help("Specify the socket address"),
        )
        .arg(
            Arg::with_name("C_SHELL")
                .short("c")
                .help("Generate commands in C-shell format"),
        )
        .arg(
            Arg::with_name("DEBUG")
                .short("d")
                .conflicts_with("KILL")
                .conflicts_with("COMMAND")
                .help("Do not fork"),
        )
        .arg(
            Arg::with_name("KILL")
                .short("k")
                .help("Kill the current instance"),
        )
        .arg(
            Arg::with_name("SHELL")
                .short("s")
                .help("Generate commands in Bourne shell format"),
        )
        .arg(
            Arg::with_name("COMMAND")
                .conflicts_with("KILL")
                .conflicts_with("DEBUG")
                .index(1),
        )
        .arg(
            Arg::with_name("ARGS")
                .allow_hyphen_values(true)
                .multiple(true)
                .requires("COMMAND")
                .index(2),
        )
        .group(ArgGroup::with_name("FORMAT").args(&["C_SHELL", "SHELL"]))
        .get_matches();

    let shell = if matches.is_present("C_SHELL")
        || env::var("SHELL")
            .map(|s| s.ends_with("csh"))
            .unwrap_or(false)
    {
        Shell::C
    } else {
        Shell::Bourne
    };

    if matches.is_present("KILL") {
        let pid = match env::var("SSH_AGENT_PID") {
            Ok(pid) => pid,
            Err(VarError::NotPresent) => {
                eprintln!("SSH_AGENT_PID not set");
                process::exit(1);
            }
            Err(VarError::NotUnicode(_)) => {
                eprintln!("SSH_AGENT_PID contains invalid characters");
                process::exit(1);
            }
        };
        let pid = match pid.parse() {
            Ok(pid) => pid,
            Err(error) => {
                eprintln!("SSH_AGENT_PID not understood: {}", error);
                process::exit(1);
            }
        };
        if let Err(error) = signal::kill(Pid::from_raw(pid), Signal::SIGTERM) {
            eprintln!("failed to kill agent process: {}", error);
            process::exit(1);
        }
        match shell {
            Shell::Bourne => {
                println!("unset SSH_AUTH_SOCK;");
                println!("unset SSH_AGENT_PID;");
            }
            Shell::C => {
                println!("unsetenv SSH_AUTH_SOCK;");
                println!("unsetenv SSH_AGENT_PID;");
            }
        }
        println!("echo killed agent process {}", pid);
        return;
    }

    let bind_address = match matches.value_of("BIND_ADDRESS") {
        Some(path) => BindAddress::Provided(Path::new(path)),
        None => {
            let mut default_path = env::temp_dir();
            // openssh uses 12 Xs, but seems to ship its own mkdtemp to support that
            default_path.push("ssh-XXXXXX");
            default_path = mkdtemp(default_path).expect("failed to create socket directory");
            default_path.push(format!("agent.{}", Pid::parent()));
            BindAddress::Temporary(default_path)
        }
    };

    let mut server_path = env::current_exe().expect("failed to find exe location");
    server_path.pop();
    server_path.push("wsl-ssh-pageant-windows.exe");
    let server_path = server_path.into_os_string();

    let listener = UnixListener::bind(&bind_address).expect("failed to bind socket");
    let server = listener
        .incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |sock| {
            let (sock_reader, sock_writer) = sock.split();

            let handle_connection = Command::new(&server_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn_async()
                .map_err(|e| format!("failed to launch server: {:?}", e))
                .into_future()
                .and_then(|mut server| {
                    let stdin = tokio::io::copy(sock_reader, server.stdin().take().unwrap())
                        .and_then(|(_, _, mut w)| future::poll_fn(move || w.shutdown()));
                    let stdout = tokio::io::copy(server.stdout().take().unwrap(), sock_writer)
                        .and_then(|(_, _, mut w)| future::poll_fn(move || w.shutdown()));

                    stdin
                        .join(stdout)
                        .select2(server.wait_with_output())
                        .map_err(|e| {
                            format!(
                                "failed communicating with server: {}",
                                match e {
                                    Either::A((e, _)) => e,
                                    Either::B((e, _)) => e,
                                }
                            )
                        })
                })
                .map(|_| ())
                .or_else(|e| {
                    eprintln!("{}", e);
                    Ok(())
                });

            tokio::spawn(handle_connection)
        });

    match matches.value_of_os("COMMAND") {
        Some(command) => {
            let mut command = Command::new(command);
            if let Some(args) = matches.values_of_os("ARGS") {
                command.args(args);
            }
            command.env("SSH_AUTH_SOCK", &bind_address);
            command.env("SSH_AGENT_PID", format!("{}", Pid::this()));
            let child = match command.spawn_async() {
                Ok(child) => child,
                Err(error) => {
                    eprintln!("failed to launch child process: {:?}", error);
                    process::exit(1);
                }
            };
            let future = child
                .wait_with_output()
                .then(|result| Ok(result))
                .inspect(|output| {
                    match output {
                        Ok(output) => match output.status.code() {
                            Some(code) => process::exit(code),
                            None => process::exit(128 + output.status.signal().unwrap()),
                        },
                        Err(error) => {
                            eprintln!("failed to monitor child process: {:?}", error);
                            process::exit(1);
                        }
                    };
                })
                .join(server)
                .map(|_| ());
            tokio::run(future);
        }
        None => {
            if matches.is_present("DEBUG") {
                write_shell(shell, &bind_address, Pid::this()).unwrap();
                tokio::run(server);
            } else {
                match unistd::fork() {
                    Ok(ForkResult::Parent { child }) => {
                        write_shell(shell, &bind_address, child).unwrap();
                    }
                    Ok(ForkResult::Child) => {
                        // close stdio
                        let null = File::open("/dev/null").unwrap();
                        unistd::dup2(null.as_raw_fd(), io::stdout().as_raw_fd()).unwrap();
                        unistd::dup2(null.as_raw_fd(), io::stderr().as_raw_fd()).unwrap();
                        unistd::dup2(null.as_raw_fd(), io::stdin().as_raw_fd()).unwrap();
                        tokio::run(server);
                    }
                    Err(error) => {
                        eprintln!("failed to fork: {:?}", error);
                        process::exit(1);
                    }
                }
            }
        }
    }
}
