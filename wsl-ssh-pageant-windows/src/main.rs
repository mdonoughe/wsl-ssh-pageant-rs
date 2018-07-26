extern crate byteorder;
extern crate rand;
extern crate winapi;

use byteorder::{BigEndian, ByteOrder};
use rand::random;
use std::ffi::{CString, OsStr};
use std::io::{self, ErrorKind, Read, Write};
use std::os::windows::prelude::*;
use std::{process, ptr, slice};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::DWORD;
use winapi::shared::windef::HWND;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE};
use winapi::um::winnt::PAGE_READWRITE;
use winapi::um::winuser::{FindWindowW, SendMessageW, COPYDATASTRUCT, WM_COPYDATA};

const MAX_MESSAGE_LENGTH: u32 = 8192;
const BUFFER_LENGTH: u32 = MAX_MESSAGE_LENGTH + 4;
const AGENT_COPYDATA_ID: ULONG_PTR = 0x804e50ba;
const SSH_AGENT_FAILURE: u8 = 5;

#[derive(Debug)]
enum BufferError {
    MessageTooLarge,
    Io(io::Error),
}

impl From<io::Error> for BufferError {
    fn from(other: io::Error) -> Self {
        BufferError::Io(other)
    }
}

fn fill_buffer<R: Read>(read: &mut R, buffer: &mut [u8]) -> Result<bool, BufferError> {
    // this weird logic is so reading 0 bytes returns false for a clean exit,
    // but reading more than 0 and less than 4 returns UnexpectedEof
    loop {
        match read.read(&mut buffer[0..4]) {
            Ok(size) if size == 0 => return Ok(false),
            Ok(size) if size == 4 => {}
            Ok(size) => read.read_exact(&mut buffer[size..4])?,
            Err(ref error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(BufferError::from(error)),
        }
        break;
    }
    let size = BigEndian::read_u32(&buffer[0..4]);
    let end = size as usize + 4;
    if buffer.len() < end {
        return Err(BufferError::MessageTooLarge);
    }
    read.read_exact(&mut buffer[4..end])?;
    Ok(true)
}

fn dump_buffer<W: Write>(write: &mut W, buffer: &[u8]) -> Result<(), BufferError> {
    let size = BigEndian::read_u32(&buffer[0..4]);
    let end = size as usize + 4;
    if buffer.len() < end {
        return Err(BufferError::MessageTooLarge);
    }
    write.write_all(&buffer[0..end])?;
    write.flush()?;
    Ok(())
}

fn write_error<W: Write>(write: &mut W) -> Result<(), ()> {
    match write.write_all(&[0, 0, 0, 1, SSH_AGENT_FAILURE]) {
        Ok(()) => Ok(()),
        Err(error) => {
            eprintln!("fatal: failed to write error response: {:?}", error);
            Err(())
        }
    }
}

struct SharedMemory {
    mapping: *mut c_void,
    view: *mut c_void,
    size: u32,
}

impl SharedMemory {
    pub fn new(name: &str, size: u32) -> Result<Self, io::Error> {
        unsafe {
            let name = OsStr::new(name)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();

            let mapping = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                PAGE_READWRITE,
                0,
                size,
                name.as_ptr(),
            );
            if mapping.is_null() {
                return Err(io::Error::last_os_error());
            }

            let view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0);
            if view.is_null() {
                CloseHandle(mapping);
                return Err(io::Error::last_os_error());
            }

            Ok(SharedMemory {
                mapping,
                view,
                size,
            })
        }
    }
}

impl AsMut<[u8]> for SharedMemory {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.view as *mut u8, self.size as usize) }
    }
}

impl AsRef<[u8]> for SharedMemory {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.view as *mut u8, self.size as usize) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.view);
            CloseHandle(self.mapping);
        }
    }
}

struct Window {
    handle: HWND,
}

impl Window {
    pub fn find(class_name: Option<&str>, window_name: Option<&str>) -> Result<Self, io::Error> {
        let class_name = class_name.map(|s| {
            OsStr::new(s)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        });
        let window_name = window_name.map(|s| {
            OsStr::new(s)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>()
        });
        unsafe {
            let handle = FindWindowW(
                class_name.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
                window_name.map(|s| s.as_ptr()).unwrap_or(ptr::null()),
            );
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Window { handle })
        }
    }

    pub fn copy_data(&self, data_id: ULONG_PTR, data: &[u8]) -> Result<(), io::Error> {
        unsafe {
            let mut copy_data = COPYDATASTRUCT {
                dwData: data_id,
                cbData: data.len() as DWORD,
                lpData: data.as_ptr() as *const c_void as *mut c_void,
            };
            let result = SendMessageW(
                self.handle,
                WM_COPYDATA,
                0,
                &mut copy_data as *mut _ as isize,
            );
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

fn body() -> Result<(), ()> {
    let name = format!("PageantRequest{:08x}{:08x}", process::id(), random::<u32>());
    let name_bytes = CString::new(name.to_string()).unwrap();
    let name_bytes = name_bytes.to_bytes_with_nul();
    let mut buffer = match SharedMemory::new(&name, BUFFER_LENGTH) {
        Ok(buffer) => buffer,
        Err(error) => {
            eprintln!("fatal: failed to allocate shared memory: {:?}", error);
            return Err(());
        }
    };

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    loop {
        match fill_buffer(&mut stdin, buffer.as_mut()) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(error) => {
                eprintln!("fatal: failed to read request: {:?}", error);
                return Err(());
            }
        }
        let window = match Window::find(None, Some("Pageant")) {
            Ok(window) => window,
            Err(error) => {
                eprintln!("could not find Pageant: {:?}", error);
                write_error(&mut stdout)?;
                continue;
            }
        };
        if let Err(error) = window.copy_data(AGENT_COPYDATA_ID, name_bytes) {
            eprintln!("failed to forward request to Pageant: {:?}", error);
            write_error(&mut stdout)?;
            continue;
        }
        if let Err(error) = dump_buffer(&mut stdout, buffer.as_ref()) {
            eprintln!("fatal: failed to write response: {:?}", error);
            return Err(());
        }
    }
}

fn main() {
    if let Err(_) = body() {
        process::exit(1);
    }
}
