use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    Poisoned,
    Unavailable,
}

struct ConcurrentBankAccountState {
    balance: i32,
}

pub struct ConcurrentBankAccount {
    state: Mutex<ConcurrentBankAccountState>,
}

impl ConcurrentBankAccount {
    /// Creates the reviewed initial state.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ConcurrentBankAccountState {
                balance: 1,
            }),
        }
    }

    /// Reads `balance` while holding the state mutex.
    pub fn get_balance(&self) -> Result<i32, LockError> {
        let state = self.state.lock().map_err(|_| LockError::Poisoned)?;
        Ok(state.balance)
    }

    /// Executes reviewed operation `Deposit` under the mutex.
    pub fn deposit(&self) -> Result<(), LockError> {
        let mut state = self.state.lock().map_err(|_| LockError::Poisoned)?;
        if !((state.balance < 2)) {
            return Err(LockError::Unavailable);
        }
        let pre_balance = state.balance;
        state.balance = pre_balance + 1;
        Ok(())
    }

    /// Executes reviewed operation `Withdraw` under the mutex.
    pub fn withdraw(&self) -> Result<(), LockError> {
        let mut state = self.state.lock().map_err(|_| LockError::Poisoned)?;
        if !((state.balance > 0)) {
            return Err(LockError::Unavailable);
        }
        let pre_balance = state.balance;
        state.balance = pre_balance - 1;
        Ok(())
    }
}
