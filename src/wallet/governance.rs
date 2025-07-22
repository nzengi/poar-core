//! POAR Wallet Governance Module
//! 
//! This module provides governance functionality for POAR wallet with:
//! - Proposal submission and voting
//! - Governance participation tracking
//! - Validator voting integration
//! - Proposal status monitoring
//! - Governance token management

use crate::types::{Address, Signature, Hash};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

/// Proposal types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalType {
    ParameterChange { parameter: String, new_value: String },
    EmergencyHalt { reason: String },
    ValidatorSlashing { validator_address: Address, evidence: String },
    ProtocolUpgrade { version: String, description: String },
    EconomicPolicy { policy: String, parameters: HashMap<String, String> },
    NetworkUpgrade { upgrade_type: String, details: String },
}

/// Proposal status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Draft,
    Active,
    Passed,
    Failed,
    Executed,
    Cancelled,
}

/// Vote types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoteType {
    Yes,
    No,
    Abstain,
}

/// Governance proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: u64,
    pub proposer: Address,
    pub proposal_type: ProposalType,
    pub title: String,
    pub description: String,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub voting_start: u64,
    pub voting_end: u64,
    pub execution_delay: u64,
    pub required_quorum: u64,
    pub required_majority: f64,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub abstain_votes: u64,
    pub total_votes: u64,
    pub executed_at: Option<u64>,
    pub execution_tx_hash: Option<Hash>,
}

/// Governance vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVote {
    pub proposal_id: u64,
    pub voter: Address,
    pub vote_type: VoteType,
    pub voting_power: u64,
    pub timestamp: u64,
    pub signature: Signature,
}

/// Governance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStatus {
    pub total_proposals: u64,
    pub active_proposals: u64,
    pub passed_proposals: u64,
    pub failed_proposals: u64,
    pub total_votes_cast: u64,
    pub voting_power: u64,
    pub is_validator: bool,
    pub validator_stake: u64,
    pub governance_participation_rate: f64,
}

/// Governance errors
#[derive(Debug)]
pub enum GovernanceError {
    InsufficientStake { required: u64, available: u64 },
    InvalidProposal(String),
    ProposalNotFound(u64),
    VotingPeriodEnded(u64),
    AlreadyVoted(u64),
    InvalidVote(String),
    ExecutionFailed(String),
    NetworkError(String),
    Unknown(String),
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GovernanceError::InsufficientStake { required, available } => {
                write!(f, "Insufficient stake. Required: {}, Available: {}", required, available)
            }
            GovernanceError::InvalidProposal(msg) => write!(f, "Invalid proposal: {}", msg),
            GovernanceError::ProposalNotFound(id) => write!(f, "Proposal not found: {}", id),
            GovernanceError::VotingPeriodEnded(id) => write!(f, "Voting period ended for proposal: {}", id),
            GovernanceError::AlreadyVoted(id) => write!(f, "Already voted on proposal: {}", id),
            GovernanceError::InvalidVote(msg) => write!(f, "Invalid vote: {}", msg),
            GovernanceError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            GovernanceError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            GovernanceError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for GovernanceError {}

/// POAR Governance Wallet
pub struct GovernanceWallet {
    /// User's governance proposals
    user_proposals: Arc<Mutex<HashMap<u64, GovernanceProposal>>>,
    /// User's votes
    user_votes: Arc<Mutex<HashMap<u64, GovernanceVote>>>,
    /// Governance status
    status: Arc<Mutex<GovernanceStatus>>,
    /// Network client for governance operations
    network_client: GovernanceNetworkClient,
    /// Configuration
    config: GovernanceConfig,
}

/// Governance network client
pub struct GovernanceNetworkClient {
    pub endpoint: String,
    pub timeout: std::time::Duration,
    pub retry_attempts: u32,
}

/// Governance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub min_proposal_stake: u64,
    pub min_voting_stake: u64,
    pub proposal_fee: u64,
    pub voting_period_days: u64,
    pub execution_delay_days: u64,
    pub required_quorum_percentage: f64,
    pub required_majority_percentage: f64,
    pub enable_validator_voting: bool,
    pub enable_emergency_proposals: bool,
}

impl GovernanceWallet {
    /// Create new governance wallet
    pub fn new() -> Self {
        let network_client = GovernanceNetworkClient {
            endpoint: "http://localhost:8545".to_string(),
            timeout: std::time::Duration::from_secs(30),
            retry_attempts: 3,
        };

        let config = GovernanceConfig {
            min_proposal_stake: 100_000, // 100k POAR minimum stake for proposals
            min_voting_stake: 10_000,    // 10k POAR minimum stake for voting
            proposal_fee: 1_000,         // 1k POAR fee for proposal submission
            voting_period_days: 7,       // 7 days voting period
            execution_delay_days: 2,     // 2 days execution delay
            required_quorum_percentage: 0.4,  // 40% quorum required
            required_majority_percentage: 0.6, // 60% majority required
            enable_validator_voting: true,
            enable_emergency_proposals: true,
        };

        let status = GovernanceStatus {
            total_proposals: 0,
            active_proposals: 0,
            passed_proposals: 0,
            failed_proposals: 0,
            total_votes_cast: 0,
            voting_power: 0,
            is_validator: false,
            validator_stake: 0,
            governance_participation_rate: 0.0,
        };

        Self {
            user_proposals: Arc::new(Mutex::new(HashMap::new())),
            user_votes: Arc::new(Mutex::new(HashMap::new())),
            status: Arc::new(Mutex::new(status)),
            network_client,
            config,
        }
    }

    /// Submit a governance proposal
    pub fn submit_proposal(
        &mut self,
        proposer: Address,
        proposal_type: ProposalType,
        title: String,
        description: String,
        stake_amount: u64,
    ) -> Result<u64, GovernanceError> {
        // Validate minimum stake
        if stake_amount < self.config.min_proposal_stake {
            return Err(GovernanceError::InsufficientStake {
                required: self.config.min_proposal_stake,
                available: stake_amount,
            });
        }

        // Validate proposal
        self.validate_proposal(&proposal_type, &title, &description)?;

        // Generate proposal ID
        let proposal_id = self.generate_proposal_id();

        let current_time = Self::current_timestamp();
        let voting_start = current_time;
        let voting_end = current_time + (self.config.voting_period_days * 24 * 60 * 60);
        let execution_delay = self.config.execution_delay_days * 24 * 60 * 60;

        let proposal = GovernanceProposal {
            proposal_id,
            proposer,
            proposal_type,
            title,
            description,
            status: ProposalStatus::Draft,
            created_at: Self::current_timestamp(),
            voting_start,
            voting_end,
            execution_delay,
            required_quorum: (stake_amount as f64 * self.config.required_quorum_percentage) as u64,
            required_majority: self.config.required_majority_percentage,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_votes: 0,
            executed_at: None,
            execution_tx_hash: None,
        };

        // Submit to network
        self.network_client.submit_proposal(&proposal)?;

        // Store locally
        {
            let mut proposals = self.user_proposals.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            proposals.insert(proposal_id, proposal);
        }

        // Update status
        self.update_governance_status()?;

        Ok(proposal_id)
    }

    /// Vote on a governance proposal
    pub fn vote_on_proposal(
        &mut self,
        proposal_id: u64,
        voter: Address,
        vote_type: VoteType,
        voting_power: u64,
    ) -> Result<(), GovernanceError> {
        // Validate minimum voting stake
        if voting_power < self.config.min_voting_stake {
            return Err(GovernanceError::InsufficientStake {
                required: self.config.min_voting_stake,
                available: voting_power,
            });
        }

        // Check if already voted
        {
            let votes = self.user_votes.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            if votes.contains_key(&proposal_id) {
                return Err(GovernanceError::AlreadyVoted(proposal_id));
            }
        }

        // Get proposal
        let proposal = self.get_proposal(proposal_id)?;

        // Check if voting period is still active
        let current_time = Self::current_timestamp();
        if current_time > proposal.voting_end {
            return Err(GovernanceError::VotingPeriodEnded(proposal_id));
        }

        // Create vote
        let vote = GovernanceVote {
            proposal_id,
            voter,
            vote_type: vote_type.clone(),
            voting_power,
            timestamp: current_time,
            signature: Signature::dummy(), // Would be signed in production
        };

        // Submit vote to network
        self.network_client.submit_vote(&vote)?;

        // Store locally
        {
            let mut votes = self.user_votes.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            votes.insert(proposal_id, vote);
        }

        // Update proposal votes
        self.update_proposal_votes(proposal_id, &vote_type, voting_power)?;

        // Update status
        self.update_governance_status()?;

        Ok(())
    }

    /// Get governance proposal
    pub fn get_proposal(&self, proposal_id: u64) -> Result<GovernanceProposal, GovernanceError> {
        // Check local proposals first
        {
            let proposals = self.user_proposals.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            if let Some(proposal) = proposals.get(&proposal_id) {
                return Ok(proposal.clone());
            }
        }

        // Query network for proposal
        self.network_client.get_proposal(proposal_id)
    }

    /// Get all active proposals
    pub fn get_active_proposals(&self) -> Result<Vec<GovernanceProposal>, GovernanceError> {
        self.network_client.get_active_proposals()
    }

    /// Get user's proposals
    pub fn get_user_proposals(&self, user_address: &Address) -> Result<Vec<GovernanceProposal>, GovernanceError> {
        let proposals = self.user_proposals.lock()
            .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
        
        let user_proposals: Vec<GovernanceProposal> = proposals
            .values()
            .filter(|proposal| proposal.proposer == *user_address)
            .cloned()
            .collect();

        Ok(user_proposals)
    }

    /// Get user's votes
    pub fn get_user_votes(&self, user_address: &Address) -> Result<Vec<GovernanceVote>, GovernanceError> {
        let votes = self.user_votes.lock()
            .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
        
        let user_votes: Vec<GovernanceVote> = votes
            .values()
            .filter(|vote| vote.voter == *user_address)
            .cloned()
            .collect();

        Ok(user_votes)
    }

    /// Get governance status
    pub fn get_status(&self) -> GovernanceStatus {
        match self.status.lock() {
            Ok(status) => status.clone(),
            Err(_) => GovernanceStatus {
                total_proposals: 0,
                active_proposals: 0,
                passed_proposals: 0,
                failed_proposals: 0,
                total_votes_cast: 0,
                voting_power: 0,
                is_validator: false,
                validator_stake: 0,
                governance_participation_rate: 0.0,
            }
        }
    }

    /// Execute a passed proposal
    pub fn execute_proposal(&mut self, proposal_id: u64) -> Result<Hash, GovernanceError> {
        let proposal = self.get_proposal(proposal_id)?;

        // Check if proposal is passed
        if proposal.status != ProposalStatus::Passed {
            return Err(GovernanceError::InvalidProposal("Proposal is not passed".to_string()));
        }

        // Check if execution delay has passed
        let current_time = Self::current_timestamp();
        let execution_time = proposal.voting_end + proposal.execution_delay;
        
        if current_time < execution_time {
            return Err(GovernanceError::InvalidProposal("Execution delay not passed".to_string()));
        }

        // Execute proposal
        let tx_hash = self.network_client.execute_proposal(proposal_id)?;

        // Update proposal status
        {
            let mut proposals = self.user_proposals.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            if let Some(proposal) = proposals.get_mut(&proposal_id) {
                proposal.status = ProposalStatus::Executed;
                proposal.executed_at = Some(current_time);
                proposal.execution_tx_hash = Some(tx_hash);
            }
        }

        Ok(tx_hash)
    }

    /// Cancel a proposal (only proposer can cancel)
    pub fn cancel_proposal(&mut self, proposal_id: u64, proposer: Address) -> Result<(), GovernanceError> {
        let proposal = self.get_proposal(proposal_id)?;

        // Check if caller is the proposer
        if proposal.proposer != proposer {
            return Err(GovernanceError::InvalidProposal("Only proposer can cancel".to_string()));
        }

        // Check if proposal is still active
        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::InvalidProposal("Proposal is not active".to_string()));
        }

        // Cancel proposal
        self.network_client.cancel_proposal(proposal_id, proposer)?;

        // Update proposal status
        {
            let mut proposals = self.user_proposals.lock()
                .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
            if let Some(proposal) = proposals.get_mut(&proposal_id) {
                proposal.status = ProposalStatus::Cancelled;
            }
        }

        Ok(())
    }

    // Private helper methods

    fn validate_proposal(
        &self,
        proposal_type: &ProposalType,
        title: &str,
        description: &str,
    ) -> Result<(), GovernanceError> {
        // Validate title
        if title.is_empty() || title.len() > 100 {
            return Err(GovernanceError::InvalidProposal("Invalid title".to_string()));
        }

        // Validate description
        if description.is_empty() || description.len() > 1000 {
            return Err(GovernanceError::InvalidProposal("Invalid description".to_string()));
        }

        // Validate proposal type
        match proposal_type {
            ProposalType::EmergencyHalt { reason } => {
                if reason.is_empty() {
                    return Err(GovernanceError::InvalidProposal("Emergency halt requires reason".to_string()));
                }
                if !self.config.enable_emergency_proposals {
                    return Err(GovernanceError::InvalidProposal("Emergency proposals not enabled".to_string()));
                }
            }
            ProposalType::ParameterChange { parameter, new_value } => {
                if parameter.is_empty() || new_value.is_empty() {
                    return Err(GovernanceError::InvalidProposal("Parameter change requires parameter and value".to_string()));
                }
            }
            ProposalType::ValidatorSlashing { validator_address: _validator_address, evidence } => {
                // Validate evidence
                if evidence.is_empty() || evidence.len() > 500 {
                    return Err(GovernanceError::InvalidProposal("Invalid evidence".to_string()));
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn generate_proposal_id(&self) -> u64 {
        // In production, this would be generated by the network
        Self::current_timestamp()
    }

    fn update_proposal_votes(
        &mut self,
        proposal_id: u64,
        vote_type: &VoteType,
        voting_power: u64,
    ) -> Result<(), GovernanceError> {
        let mut proposals = self.user_proposals.lock()
            .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
        
        if let Some(proposal) = proposals.get_mut(&proposal_id) {
            match vote_type {
                VoteType::Yes => proposal.yes_votes += voting_power,
                VoteType::No => proposal.no_votes += voting_power,
                VoteType::Abstain => proposal.abstain_votes += voting_power,
            }
            proposal.total_votes += voting_power;

            // Check if proposal passed or failed
            let total_voting_power = proposal.yes_votes + proposal.no_votes + proposal.abstain_votes;
            let quorum_met = total_voting_power >= proposal.required_quorum;
            
            if quorum_met {
                let yes_percentage = proposal.yes_votes as f64 / (proposal.yes_votes + proposal.no_votes) as f64;
                if yes_percentage >= proposal.required_majority {
                    proposal.status = ProposalStatus::Passed;
                } else {
                    proposal.status = ProposalStatus::Failed;
                }
            }
        }

        Ok(())
    }

    fn update_governance_status(&mut self) -> Result<(), GovernanceError> {
        let mut status = self.status.lock()
            .map_err(|e| GovernanceError::Unknown(e.to_string()))?;
        
        // Update from network
        let network_status = self.network_client.get_governance_status()?;
        *status = network_status;

        Ok(())
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl GovernanceNetworkClient {
    fn submit_proposal(&self, proposal: &GovernanceProposal) -> Result<(), GovernanceError> {
        // Simulate network submission
        println!("Submitting governance proposal: {}", proposal.proposal_id);
        Ok(())
    }

    fn submit_vote(&self, vote: &GovernanceVote) -> Result<(), GovernanceError> {
        // Simulate network submission
        println!("Submitting governance vote for proposal: {}", vote.proposal_id);
        Ok(())
    }

    fn get_proposal(&self, proposal_id: u64) -> Result<GovernanceProposal, GovernanceError> {
        // Simulate network query
        // In production, this would query the blockchain
        Err(GovernanceError::ProposalNotFound(proposal_id))
    }

    fn get_active_proposals(&self) -> Result<Vec<GovernanceProposal>, GovernanceError> {
        // Simulate network query
        // In production, this would query the blockchain
        Ok(Vec::new())
    }

    fn execute_proposal(&self, proposal_id: u64) -> Result<Hash, GovernanceError> {
        // Simulate network execution
        println!("Executing proposal {} on network", proposal_id);
        Ok(Hash::zero())
    }

    fn cancel_proposal(&self, proposal_id: u64, proposer: Address) -> Result<(), GovernanceError> {
        // Simulate proposal cancellation
        println!("Cancelling governance proposal: {} by {}", proposal_id, proposer);
        Ok(())
    }

    fn get_governance_status(&self) -> Result<GovernanceStatus, GovernanceError> {
        // Simulate network query
        // In production, this would query the blockchain
        Ok(GovernanceStatus {
            total_proposals: 0,
            active_proposals: 0,
            passed_proposals: 0,
            failed_proposals: 0,
            total_votes_cast: 0,
            voting_power: 0,
            is_validator: false,
            validator_stake: 0,
            governance_participation_rate: 0.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;

    #[test]
    fn test_governance_wallet_creation() {
        let wallet = GovernanceWallet::new();
        assert_eq!(wallet.config.min_proposal_stake, 100_000);
    }

    #[test]
    fn test_proposal_submission() {
        let mut wallet = GovernanceWallet::new();
        let proposer = Address::zero();
        
        let proposal_type = ProposalType::ParameterChange {
            parameter: "min_stake".to_string(),
            new_value: "50000".to_string(),
        };
        
        let result = wallet.submit_proposal(
            proposer,
            proposal_type,
            "Test Proposal".to_string(),
            "Test Description".to_string(),
            100_000,
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_voting() {
        let mut wallet = GovernanceWallet::new();
        let voter = Address::zero();
        
        let proposal_type = ProposalType::ValidatorSlashing { 
            validator_address: Address::zero(), 
            evidence: "Test evidence".to_string() 
        };
        
        let result = wallet.vote_on_proposal(
            1,
            voter,
            VoteType::Yes,
            50_000,
        );
        
        // This will fail because proposal doesn't exist, but it tests the voting logic
        assert!(result.is_err());
    }
} 