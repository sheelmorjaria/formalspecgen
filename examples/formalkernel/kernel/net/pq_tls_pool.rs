// Copyright 2026 Sheel Morjaria
// SPDX-License-Identifier: Apache-2.0
//! Bounded admission control around an unverified liboqs TLS adapter.

/// Exact concurrent-handshake ceiling proved against each hardware profile.
pub const TLS_SESSION_CAPACITY: usize = 2;

/// Admission failure matching lwIP/mbedTLS resource backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsPoolError {
    /// Every statically budgeted handshake slot is occupied.
    ErrMem,
    /// A slot identifier was stale or already released.
    InvalidSession,
}

/// Opaque identifier; cryptographic buffers remain inside the external adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(usize);

/// Fixed-capacity admission ledger with no dynamic allocation.
pub struct TlsSessionPool {
    occupied: [bool; TLS_SESSION_CAPACITY],
}

impl TlsSessionPool {
    /// Construct a pool with every handshake slot available.
    pub const fn new() -> Self {
        Self {
            occupied: [false; TLS_SESSION_CAPACITY],
        }
    }

    /// Admit one handshake or return deterministic `ERR_MEM` backpressure.
    pub fn acquire(&mut self) -> Result<SessionId, TlsPoolError> {
        for (index, occupied) in self.occupied.iter_mut().enumerate() {
            if !*occupied {
                *occupied = true;
                return Ok(SessionId(index));
            }
        }
        Err(TlsPoolError::ErrMem)
    }

    /// Release exactly one live session slot.
    pub fn release(&mut self, session: SessionId) -> Result<(), TlsPoolError> {
        let occupied = self
            .occupied
            .get_mut(session.0)
            .ok_or(TlsPoolError::InvalidSession)?;
        if !*occupied {
            return Err(TlsPoolError::InvalidSession);
        }
        *occupied = false;
        Ok(())
    }

    /// Report bounded occupancy without exposing cryptographic material.
    pub fn active(&self) -> usize {
        self.occupied.iter().filter(|occupied| **occupied).count()
    }
}

impl Default for TlsSessionPool {
    fn default() -> Self {
        Self::new()
    }
}
