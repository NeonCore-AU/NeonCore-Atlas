use std::{
    cell::RefCell,
    mem,
    ops::{Deref, DerefMut},
};

const MAX_RETAINED_BUFFERS: usize = 64;
const MAX_RETAINED_CAPACITY: usize = 256 * 1024;

thread_local! {
    static BYTE_BUFFER_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

pub struct PooledBuffer {
    buffer: Vec<u8>,
}

impl PooledBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        let buffer = BYTE_BUFFER_POOL
            .with(|pool| pool.borrow_mut().pop())
            .unwrap_or_default();
        let mut buffer = buffer;
        buffer.clear();
        if buffer.capacity() < capacity {
            buffer.reserve(capacity - buffer.capacity());
        }
        Self { buffer }
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut self.buffer)
    }
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if self.buffer.capacity() > MAX_RETAINED_CAPACITY {
            return;
        }
        let mut buffer = mem::take(&mut self.buffer);
        buffer.clear();
        BYTE_BUFFER_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < MAX_RETAINED_BUFFERS {
                pool.push(buffer);
            }
        });
    }
}
