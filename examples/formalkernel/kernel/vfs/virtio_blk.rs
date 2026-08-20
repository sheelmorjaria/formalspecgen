// UNVERIFIED EXTERNAL BOUNDARY
//! User-space virtio-blk adapter. Device behavior is deliberately unproved.

/// Maximum requests admitted before IPC backpressure is returned.
pub const REQUEST_CAPACITY: u8 = 2;

/// A bounded block request passed through the verified syscall door.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRequest {
    /// Sector number interpreted by the external device.
    pub sector: u64,
    /// Index of a kernel-confined DMA buffer.
    pub buffer_id: u8,
    /// Whether the operation writes rather than reads.
    pub write: bool,
}

/// Fail-closed errors exposed to the VFS server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError {
    /// Every statically allocated request slot is occupied.
    QueueFull,
    /// The kernel rejected the request at the syscall boundary.
    BoundaryRejected,
    /// Completion was reported while no request was outstanding.
    UnexpectedCompletion,
}

/// Narrow syscall capability supplied by the kernel-facing runtime.
pub trait BlockSyscall {
    /// Submit one request without exposing a physical DMA address.
    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError>;
}

/// Storage interface consumed by the VFS server.
pub trait BlockDevice {
    /// Submit one bounded request.
    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError>;
    /// Retire one completed request.
    fn complete(&mut self) -> Result<(), DriverError>;
}

/// Unverified device glue constrained to a verified syscall capability.
pub struct VirtioBlkAdapter<P: BlockSyscall> {
    port: P,
    in_flight: u8,
}

impl<P: BlockSyscall> VirtioBlkAdapter<P> {
    /// Construct an empty bounded adapter.
    pub fn new(port: P) -> Self {
        Self { port, in_flight: 0 }
    }

    /// Current bounded occupancy, exposed for deterministic integration tests.
    pub fn in_flight(&self) -> u8 {
        self.in_flight
    }
}

impl<P: BlockSyscall> BlockDevice for VirtioBlkAdapter<P> {
    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError> {
        if self.in_flight >= REQUEST_CAPACITY {
            return Err(DriverError::QueueFull);
        }
        self.port.submit(request)?;
        self.in_flight += 1;
        Ok(())
    }

    fn complete(&mut self) -> Result<(), DriverError> {
        if self.in_flight == 0 {
            return Err(DriverError::UnexpectedCompletion);
        }
        self.in_flight -= 1;
        Ok(())
    }
}
