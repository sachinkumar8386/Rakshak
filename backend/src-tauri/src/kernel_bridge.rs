/// Rakshak Kernel Bridge (v2)
///
/// Implements the User-mode side of the FltComm Communication Port.
/// This bridge allows the Rakshak Engine to receive synchronous I/O 
/// interception requests from the rakshak_driver.sys Minifilter.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{NTSTATUS, HANDLE};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage,
    FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER
};

#[repr(C)]
pub struct RakshakMessage {
    pub header: FILTER_MESSAGE_HEADER,
    pub pid: u32,
    pub path_len: u32,
    pub path: [u16; 260],
}

#[repr(C)]
pub struct RakshakReply {
    pub header: FILTER_REPLY_HEADER,
    pub allow: u32, // 1 = Allow, 0 = Block
}

pub struct KernelBridge {
    port: HANDLE,
}

impl KernelBridge {
    pub fn connect() -> Result<Self, String> {
        let port_name: Vec<u16> = "\\RakshakCommPort\0".encode_utf16().collect();
        
        unsafe {
            // windows-rs 0.58.0 returns Result<HANDLE> for this function
            let result = FilterConnectCommunicationPort(
                PCWSTR(port_name.as_ptr()),
                0,
                None,
                0,
                None
            );
            
            match result {
                Ok(port) => Ok(Self { port }),
                Err(e) => Err(format!("Failed to connect to Rakshak Driver port: {:?}", e)),
            }
        }
    }

    pub fn listen(&self) {
        log::info!("KernelBridge: Listening for synchronous IRP requests...");
        let mut msg = RakshakMessage {
            header: unsafe { std::mem::zeroed() },
            pid: 0,
            path_len: 0,
            path: [0; 260],
        };

        unsafe {
            loop {
                // FilterGetMessage returns windows::core::Result<()>
                let hr = FilterGetMessage(
                    self.port,
                    &mut msg.header,
                    std::mem::size_of::<RakshakMessage>() as u32,
                    None
                );

                if hr.is_ok() {
                    self.handle_irp_request(&msg);
                }
            }
        }
    }

    fn handle_irp_request(&self, msg: &RakshakMessage) {
        log::info!("KernelBridge: Received intercept request for PID {}", msg.pid);
        
        let reply = RakshakReply {
            header: FILTER_REPLY_HEADER {
                Status: NTSTATUS(0),
                MessageId: msg.header.MessageId,
            },
            allow: 1, // Defaulting to Allow for safety during scaffolding
        };

        unsafe {
            let _ = FilterReplyMessage(
                self.port,
                &reply.header,
                std::mem::size_of::<RakshakReply>() as u32
            );
        }
    }
}
