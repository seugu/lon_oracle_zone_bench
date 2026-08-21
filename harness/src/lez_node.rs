//! A single-node LEZ chain driven by the real state machine.
//!
//! There is no reimplementation here: the node holds a `lee::V03State`, deploys
//! the program with a `ProgramDeploymentTransaction`, and applies every
//! transaction through `V03State::transition_from_public_transaction` — the same
//! call the sequencer service makes when it builds a block. That path verifies
//! the transaction signatures, checks nonces, builds the pre-states, executes
//! the program's RISC-V image in the RISC Zero zkVM, runs `validate_execution`,
//! resolves PDA claims and commits the state diff.
//!
//! What is missing relative to a live testnet is everything *around* execution —
//! Bedrock/DA, block production and finality, the mempool and its ordering, the
//! RPC and indexer, and therefore network delay and concurrent submitters. The
//! execution and state-transition semantics themselves are the production ones.

use anyhow::{anyhow, Result};
use nssa::program::Program;
use nssa::program_deployment_transaction::{
    Message as DeploymentMessage, ProgramDeploymentTransaction,
};
use nssa::public_transaction::{Message, WitnessSet};
use nssa::{AccountId, PrivateKey, PublicKey, PublicTransaction, V03State};
use std::borrow::Cow;
use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::ProgramId;
use risc0_zkvm::{default_executor, ExecutorEnv};

/// Mirrors `MAX_NUM_CYCLES_PUBLIC_EXECUTION` in `lee::program` — the budget a
/// single public execution may not exceed. This constant is the reason the
/// program caps signatures per transaction.
pub const MAX_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32;

/// What the node reports back for one submitted transaction.
#[derive(Debug)]
pub struct Receipt {
    pub label: String,
    pub accepted: bool,
    pub error: Option<String>,
    /// zkVM cycles the execution consumed, when measurement is enabled.
    pub cycles: Option<u64>,
}

impl Receipt {
    /// Cycle count as a share of the public-execution budget.
    #[must_use]
    pub fn budget_share(&self) -> Option<f64> {
        self.cycles
            .map(|c| c as f64 / MAX_CYCLES_PUBLIC_EXECUTION as f64)
    }
}

pub struct LezNode {
    state: V03State,
    program_id: ProgramId,
    /// The deployed bytecode — a RISC Zero `ProgramBinary` (user ELF + kernel).
    program_binary: Vec<u8>,
    block_id: u64,
    timestamp: u64,
    measure: bool,
}

impl LezNode {
    /// Boots a chain with the given genesis accounts and deploys the program.
    pub fn boot(
        program_binary: Vec<u8>,
        genesis: &[(AccountId, u128)],
        measure: bool,
    ) -> Result<Self> {
        let program = Program::new(Cow::Owned(program_binary.clone()))
            .map_err(|e| anyhow!("invalid bytecode: {e}"))?;
        let program_id = program.id();

        let timestamp = 1_700_000_000;
        let mut state = V03State::new().with_public_account_balances(genesis.iter().copied());

        let deployment = ProgramDeploymentTransaction::new(DeploymentMessage::new(
            program_binary.clone(),
        ));
        state
            .transition_from_program_deployment_transaction(&deployment)
            .map_err(|e| anyhow!("program deployment rejected: {e}"))?;

        Ok(Self {
            state,
            program_id,
            program_binary,
            block_id: 1,
            timestamp,
            measure,
        })
    }

    #[must_use]
    pub const fn program_id(&self) -> ProgramId {
        self.program_id
    }

    #[must_use]
    pub fn account(&self, id: AccountId) -> Account {
        self.state.get_account_by_id(id)
    }

    /// Signs and submits one public transaction.
    pub fn send<T: serde::Serialize>(
        &mut self,
        label: &str,
        account_ids: Vec<AccountId>,
        signer: &PrivateKey,
        instruction: T,
    ) -> Receipt {
        let signer_id = AccountId::from(&PublicKey::new_from_private_key(signer));
        let nonces = vec![self.account(signer_id).nonce];

        let message = match Message::try_new(self.program_id, account_ids, nonces, instruction) {
            Ok(m) => m,
            Err(e) => {
                return Receipt {
                    label: label.to_string(),
                    accepted: false,
                    error: Some(format!("message build failed: {e}")),
                    cycles: None,
                }
            }
        };
        let witness_set = WitnessSet::for_message(&message, &[signer]);
        let tx = PublicTransaction::new(message, witness_set);

        // Measured on a separate executor run with the same inputs the node
        // will feed the program, so the number matches what the node executes.
        let cycles = if self.measure {
            self.measure_cycles(&tx, signer_id).ok()
        } else {
            None
        };

        match self
            .state
            .transition_from_public_transaction(&tx, self.block_id, self.timestamp)
        {
            Ok(()) => {
                self.block_id = self.block_id.saturating_add(1);
                self.timestamp = self.timestamp.saturating_add(1);
                Receipt {
                    label: label.to_string(),
                    accepted: true,
                    error: None,
                    cycles,
                }
            }
            Err(e) => Receipt {
                label: label.to_string(),
                accepted: false,
                error: Some(format!("{e}")),
                cycles,
            },
        }
    }

    /// Runs the program image directly to read the cycle count.
    ///
    /// The input order mirrors `lee::program::Program::write_inputs`.
    fn measure_cycles(&self, tx: &PublicTransaction, signer_id: AccountId) -> Result<u64> {
        let message = tx.message();
        let pre_states: Vec<AccountWithMetadata> = message
            .account_ids
            .iter()
            .map(|id| AccountWithMetadata::new(self.account(*id), *id == signer_id, *id))
            .collect();
        let caller_program_id: Option<ProgramId> = None;

        let env = ExecutorEnv::builder()
            .write(&self.program_id)?
            .write(&caller_program_id)?
            .write(&pre_states)?
            .write(&message.instruction_data)?
            .session_limit(Some(MAX_CYCLES_PUBLIC_EXECUTION))
            // The node will execute this same program again to apply the
            // transaction; silence the guest's stdout here so its log lines
            // appear once, not twice.
            .stdout(std::io::sink())
            .build()?;

        let session = default_executor()
            .execute(env, &self.program_binary)
            .map_err(|e| anyhow!("{e}"))?;
        Ok(session.cycles())
    }
}
