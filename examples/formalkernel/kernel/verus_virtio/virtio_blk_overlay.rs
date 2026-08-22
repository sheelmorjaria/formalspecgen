// UNVERIFIED EXTERNAL BOUNDARY
//! User-space virtio-blk adapter. Device behavior is deliberately unproved.

/* VERUS_OVERLAY_BEGIN:crate */
use vstd::prelude::*;

verus! {
/* VERUS_OVERLAY_END:crate */
/* VERUS_OVERLAY_BEGIN:reviewed_model_relation */
// queue_model.candidate.json sha256:
// 191566f356e440aa074c44eae49b9088e0673706ce5e9b051152fe964b569b0e
pub open spec fn model_submit_post(pre: int, accepted: bool) -> int {
    if accepted { pre + 1 } else { pre }
}

pub open spec fn model_complete_post(pre: int) -> int {
    if pre > 0 { pre - 1 } else { pre }
}
/* VERUS_OVERLAY_END:reviewed_model_relation */
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
    /* VERUS_OVERLAY_REPLACE:    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError>; */
    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError>
        no_unwind
    ;
    /* VERUS_OVERLAY_REPLACE_END */
}

/// Storage interface consumed by the VFS server.
pub trait BlockDevice {
    /* VERUS_OVERLAY_BEGIN:block_device_view */
    spec fn queue_depth(&self) -> int;
    /* VERUS_OVERLAY_END:block_device_view */
    /// Submit one bounded request.
    /* VERUS_OVERLAY_REPLACE:    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError>; */
    fn submit(&mut self, request: BlockRequest) -> (result: Result<(), DriverError>)
        ensures
            result is Ok ==> old(self).queue_depth() < REQUEST_CAPACITY,
            result is Ok ==> final(self).queue_depth() == old(self).queue_depth() + 1,
            result is Err ==> final(self).queue_depth() == old(self).queue_depth(),
            final(self).queue_depth() == model_submit_post(
                old(self).queue_depth(), result is Ok),
        no_unwind
    ;
    /* VERUS_OVERLAY_REPLACE_END */
    /// Retire one completed request.
    /* VERUS_OVERLAY_REPLACE:    fn complete(&mut self) -> Result<(), DriverError>; */
    fn complete(&mut self) -> (result: Result<(), DriverError>)
        ensures
            old(self).queue_depth() == 0 ==> result is Err,
            old(self).queue_depth() == 0 ==> final(self).queue_depth() == old(self).queue_depth(),
            old(self).queue_depth() > 0 ==> result is Ok,
            old(self).queue_depth() > 0 ==> final(self).queue_depth() == old(self).queue_depth() - 1,
            final(self).queue_depth() == model_complete_post(old(self).queue_depth()),
        no_unwind
    ;
    /* VERUS_OVERLAY_REPLACE_END */
}

/// Unverified device glue constrained to a verified syscall capability.
pub struct VirtioBlkAdapter<P: BlockSyscall> {
    port: P,
    in_flight: u8,
}

impl<P: BlockSyscall> VirtioBlkAdapter<P> {
    /* VERUS_OVERLAY_BEGIN:adapter_invariant */
    #[verifier::type_invariant]
    closed spec fn queue_invariant(&self) -> bool {
        0 <= self.in_flight <= REQUEST_CAPACITY
    }
    /* VERUS_OVERLAY_END:adapter_invariant */
    /// Construct an empty bounded adapter.
    /* VERUS_OVERLAY_REPLACE:    pub fn new(port: P) -> Self { */
    pub fn new(port: P) -> (result: Self)
        ensures
            result.queue_depth() == 0,
    {
    /* VERUS_OVERLAY_REPLACE_END */
        Self { port, in_flight: 0 }
    }

    /// Current bounded occupancy, exposed for deterministic integration tests.
    /* VERUS_OVERLAY_REPLACE:    pub fn in_flight(&self) -> u8 { */
    pub fn in_flight(&self) -> (result: u8)
        ensures
            result as int == self.queue_depth(),
    {
    /* VERUS_OVERLAY_REPLACE_END */
        self.in_flight
    }
}

impl<P: BlockSyscall> BlockDevice for VirtioBlkAdapter<P> {
    /* VERUS_OVERLAY_BEGIN:block_device_view_impl */
    closed spec fn queue_depth(&self) -> int {
        self.in_flight as int
    }
    /* VERUS_OVERLAY_END:block_device_view_impl */
    /* VERUS_OVERLAY_REPLACE:    fn submit(&mut self, request: BlockRequest) -> Result<(), DriverError> { */
    fn submit(&mut self, request: BlockRequest) -> (result: Result<(), DriverError>) {
    /* VERUS_OVERLAY_REPLACE_END */
        /* VERUS_OVERLAY_BEGIN:submit_open_invariant */
        proof { use_type_invariant(&*self); }
        /* VERUS_OVERLAY_END:submit_open_invariant */
        if self.in_flight >= REQUEST_CAPACITY {
            return Err(DriverError::QueueFull);
        }
        self.port.submit(request)?;
        self.in_flight += 1;
        Ok(())
    }

    /* VERUS_OVERLAY_REPLACE:    fn complete(&mut self) -> Result<(), DriverError> { */
    fn complete(&mut self) -> (result: Result<(), DriverError>) {
    /* VERUS_OVERLAY_REPLACE_END */
        /* VERUS_OVERLAY_BEGIN:complete_open_invariant */
        proof { use_type_invariant(&*self); }
        /* VERUS_OVERLAY_END:complete_open_invariant */
        if self.in_flight == 0 {
            return Err(DriverError::UnexpectedCompletion);
        }
        /* VERUS_OVERLAY_BEGIN:complete_invariant_hint */
        proof {
            assert(1 <= self.in_flight <= REQUEST_CAPACITY);
        }
        /* VERUS_OVERLAY_END:complete_invariant_hint */
        self.in_flight -= 1;
        Ok(())
    }
}
/* VERUS_OVERLAY_BEGIN:crate_end */
} // verus!

fn main() {}
/* VERUS_OVERLAY_END:crate_end */
