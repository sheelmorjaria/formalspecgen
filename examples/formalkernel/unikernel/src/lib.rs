// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
#![no_std]

#[cfg(not(feature = "unikernel"))]
compile_error!("the FormalKernel single-address-space image requires --features unikernel");

/// Execution level of the single-address-space profile.
pub const EXECUTION_LEVEL: u8 = 1;

/// Services linked directly into the EL1 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    /// Bounded virtual filesystem.
    Vfs,
    /// Bounded network stack.
    Net,
}

/// Dispatch a direct in-image service call without syscall or IPC machinery.
#[must_use]
pub const fn direct_service_call(service: Service) -> u8 {
    match service {
        Service::Vfs => 1,
        Service::Net => 2,
    }
}
