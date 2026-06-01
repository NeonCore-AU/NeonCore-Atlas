use neoncore_tun::{TunDecision, TunEngine};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read},
    os::fd::FromRawFd,
};

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 40],
}

pub struct LinuxTunDevice {
    file: File,
}

impl LinuxTunDevice {
    pub fn open(name: &str) -> io::Result<Self> {
        let path = CString::new("/dev/net/tun").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 40],
        };
        for (index, byte) in name.bytes().take(IFNAMSIZ - 1).enumerate() {
            request.name[index] = byte as libc::c_char;
        }
        let result = unsafe { libc::ioctl(fd, TUNSETIFF, &request) };
        if result < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self { file })
    }

    pub fn read_decision(&mut self, engine: &TunEngine, buffer: &mut [u8]) -> io::Result<TunDecision> {
        let len = self.file.read(buffer)?;
        Ok(engine.inspect_packet(&buffer[..len]))
    }
}
