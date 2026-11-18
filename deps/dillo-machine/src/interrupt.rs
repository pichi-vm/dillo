// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Interrupt declarations and resolved delivery services.

use std::sync::Arc;

/// DTB-derived interrupt source for one wired interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptSource {
    pub controller: u32,
    pub cells: [u32; 4],
    pub cell_count: u8,
}

/// DTB-derived interrupt source for one message-interrupt domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInterruptSource {
    pub controller: u32,
}

/// One DTB-derived interrupt requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptRequirement {
    Line {
        source: InterruptSource,
    },

    MessageDomain {
        source: Option<MessageInterruptSource>,
        vectors: u16,
    },
}

/// Resolved interrupt handle.
#[derive(Clone)]
pub struct Interrupt(Arc<dyn InterruptLine>);

impl std::fmt::Debug for Interrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Interrupt").finish()
    }
}

impl Interrupt {
    pub fn new(line: Arc<dyn InterruptLine>) -> Self {
        Self(line)
    }

    pub fn from_fn(signal: impl Fn() + Send + Sync + 'static) -> Self {
        Self::new(Arc::new(FnInterruptLine {
            signal: Box::new(signal),
        }))
    }

    pub fn signal(&self) {
        self.0.signal();
    }

    pub fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        self.0.set_level(level)
    }
}

struct FnInterruptLine {
    signal: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for FnInterruptLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnInterruptLine").finish_non_exhaustive()
    }
}

impl InterruptLine for FnInterruptLine {
    fn signal(&self) {
        (self.signal)();
    }

    fn set_level(&self, level: bool) -> Result<(), InterruptError> {
        if level {
            self.signal();
        }
        Ok(())
    }
}

/// Backend-resolved line interrupt.
pub trait InterruptLine: Send + Sync + std::fmt::Debug {
    fn signal(&self);

    fn set_level(&self, level: bool) -> Result<(), InterruptError>;
}

/// Error from interrupt delivery.
#[derive(Debug, thiserror::Error)]
pub enum InterruptError {
    #[error("interrupt deassert is unsupported")]
    UnsupportedDeassert,

    #[error("interrupt delivery failed: {0}")]
    Delivery(String),
}

/// Resolved message interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInterrupt {
    pub address: u64,
    pub data: u32,
    pub masked: bool,
}

/// Backend-resolved message-interrupt domain.
pub trait MessageInterruptDomain: Send + Sync {
    fn update(&self, vector: u16, msg: MessageInterrupt) -> Result<(), InterruptError>;

    /// Set the effective enable state for one vector independently of its mask.
    /// Changes must not affect other vectors in the domain.
    fn enabled(&self, vector: u16, enabled: bool) -> Result<(), InterruptError>;

    fn interrupt(&self, vector: u16) -> Option<Interrupt>;
}

/// Backend-resolved interrupt resource for an attached device.
#[derive(Clone)]
pub enum InterruptResource {
    Line(Interrupt),

    MessageDomain(Arc<dyn MessageInterruptDomain>),
}

impl std::fmt::Debug for InterruptResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Line(line) => f.debug_tuple("Line").field(line).finish(),
            Self::MessageDomain(_) => f.debug_tuple("MessageDomain").finish(),
        }
    }
}
