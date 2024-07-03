// Import necessary dependencies
#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

// Use these types to store our canister's state and generate unique IDs
type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// Define the admin struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Admin {
    id: u64,
    name: String,
    email: String,
    created_at: u64,
}

impl Storable for Admin {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Admin {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Group struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Group {
    id: u64,
    name: String,
    admin_id: String,
    members: Vec<String>,
    created_at: u64,
}

impl Storable for Group {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Group {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Member struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Member {
    id: u64,
    name: String,
    email: String,
    points: u64, // New field for points
    created_at: u64,
}

impl Storable for Member {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Member {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Contribution struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Contribution {
    id: u64,
    group_id: u64,
    member_id: u64,
    amount: f64,
    created_at: u64,
}

impl Storable for Contribution {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Contribution {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Proposal struct
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Proposal {
    id: u64,
    group_id: u64,
    proposer_id: u64,
    description: String,
    votes_for: u64,
    votes_against: u64,
    created_at: u64,
}

impl Storable for Proposal {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Proposal {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define payloads

// Admin Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct AdminPayload {
    name: String,
    email: String,
}

// Group Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct GroupPayload {
    name: String,
    admin_id: String,
}

// Member Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct MemberPayload {
    name: String,
    email: String,
}

// Contribution Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct ContributionPayload {
    group_id: u64,
    member_id: u64,
    amount: f64,
}

// Proposal Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct ProposalPayload {
    group_id: u64,
    proposer_id: u64,
    description: String,
}

// Vote Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct VotePayload {
    proposal_id: u64,
    member_id: u64,
    vote: bool, // true for 'for', false for 'against'
}

// Add Member to Group Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct AddMemberToGroupPayload {
    group_id: u64,
    member_id: u64,
}

// Thread-local variables that will hold our canister's state
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static ADMIN_STORAGE: RefCell<StableBTreeMap<u64, Admin, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
    ));

    static GROUPS_STORAGE: RefCell<StableBTreeMap<u64, Group, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static MEMBERS_STORAGE: RefCell<StableBTreeMap<u64, Member, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static CONTRIBUTIONS_STORAGE: RefCell<StableBTreeMap<u64, Contribution, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static PROPOSALS_STORAGE: RefCell<StableBTreeMap<u64, Proposal, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));
}

// Error handling enum
#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    UnAuthorized { msg: String },
    NotFound { msg: String },
    EmptyFields { msg: String },
    NotGroupMember { msg: String },
    AlreadyExists { msg: String },
    InvalidEmail { msg: String },
    InvalidName { msg: String },
}

// Function to create a group ADMIN
#[ic_cdk::update]
fn create_admin(payload: AdminPayload) -> Result<Admin, Error> {
    if payload.name.is_empty() || payload.email.is_empty() {
        return Err(Error::EmptyFields {
            msg: "Name and email are required".to_string(),
        });
    }

    // Validate the email address
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(Error::InvalidEmail {
            msg: "Ensure the email address is of the correct format".to_string(),
        });
    }

    // Ensure the email address is unique
    let email_exists = ADMIN_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.email == payload.email)
    });
    if email_exists {
        return Err(Error::AlreadyExists {
            msg: "Email address already in use".to_string(),
        });
    }

    // Validate the name
    let name_regex = Regex::new(r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$").unwrap();
    if !name_regex.is_match(&payload.name) {
        return Err(Error::InvalidName {
            msg: "Invalid name".to_string(),
        });
    }

    // Generate unique IDs for admins
    let id = ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    });

    // Create a new admin
    let admin = Admin {
        id,
        name: payload.name,
        email: payload.email,
        created_at: get_current_time(),
    };

    // Store the admin in the memory
    ADMIN_STORAGE.with(|storage| storage.borrow_mut().insert(id, admin.clone()));
    Ok(admin)
}

// Function to update admin details
#[ic_cdk::update]
fn update_admin(payload: AdminPayload) -> Result<Admin, Error> {
    if payload.name.is_empty() || payload.email.is_empty() {
        return Err(Error::EmptyFields {
            msg: "Name and email are required".to_string(),
        });
    }

    // Validate the email address
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(Error::InvalidEmail {
            msg: "Ensure the email address is of the correct format".to_string(),
        });
    }

    // Ensure the email address is unique
    let email_exists = ADMIN_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.email == payload.email)
    });
    if email_exists {
        return Err(Error::AlreadyExists {
            msg: "Email address already in use".to_string(),
        });
    }

    // Validate the name
    let name_regex = Regex::new(r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$").unwrap();
    if !name_regex.is_match(&payload.name) {
        return Err(Error::InvalidName {
            msg: "Invalid name".to_string(),
        });
    }

    // Ensure the admin exists
    let admin_exists = ADMIN_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.email == payload.email)
    });
    if !admin_exists {
        return Err(Error::NotFound {
            msg: "Admin not found".to_string(),
        });
    }

    // Update the admin details
    let admin = ADMIN_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        let admin = storage
            .iter()
            .find(|(_, admin)| admin.email == payload.email)
            .unwrap()
            .1
            .clone();

        let updated_admin = Admin {
            id: admin.id,
            name: payload.name,
            email: payload.email,
            created_at: admin.created_at,
        };

        storage.insert(admin.id, updated_admin.clone());
        updated_admin
    });

    Ok(admin)
}

// Function to create a new group (Only admins create groups)
#[ic_cdk::update]
fn create_group(payload: GroupPayload) -> Result<Group, Error> {
    if payload.name.is_empty() {
        return Err(Error::EmptyFields {
            msg: "Ensure all fields are filled".to_string(),
        });
    }

    // Ensure the admin exists
    let admin_exists = ADMIN_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.id.to_string() == payload.admin_id)
    });
    if !admin_exists {
        return Err(Error::UnAuthorized {
            msg: "Unauthorized access".to_string(),
        });
    }

    // Generate unique IDs for groups
    let id = ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    });

    // Create a new group
    let group = Group {
        id,
        name: payload.name,
        admin_id: payload.admin_id,
        members: vec![],
        created_at: get_current_time(),
    };

    // Store the group in the memory
    GROUPS_STORAGE.with(|storage| storage.borrow_mut().insert(id, group.clone()));
    Ok(group)
}

// Adds a new member with the provided payload
#[ic_cdk::update]
fn add_member(payload: MemberPayload) -> Result<Member, Error> {
    if payload.name.is_empty() || payload.email.is_empty() {
        return Err(Error::EmptyFields {
            msg: "Name and email are required".to_string(),
        });
    }

    // Validate the email address
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(Error::InvalidEmail {
            msg: "Ensure the email address is of the correct format".to_string(),
        });
    }

    // Ensure unique email address
    let email_exists = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, member)| member.email == payload.email)
    });

    if email_exists {
        return Err(Error::AlreadyExists {
            msg: "Email address already in use".to_string(),
        });
    }

    let id = ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    });

    let member = Member {
        id,
        name: payload.name,
        email: payload.email,
        points: 0, // Initialize points to 0
        created_at: get_current_time(),
    };

    MEMBERS_STORAGE.with(|storage| storage.borrow_mut().insert(id, member.clone()));
    Ok(member)
}

// Function to add  a member to a group (Only admins can add members to groups)
#[ic_cdk::update]
fn add_member_to_group(payload: AddMemberToGroupPayload) -> Result<Member, Error> {
    // Ensure the group exists
    let group_exists = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, group)| group.id == payload.group_id)
    });

    if !group_exists {
        return Err(Error::NotFound {
            msg: "Group not found".to_string(),
        });
    }

    // Ensure the member exists
    let member_exists = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, member)| member.id == payload.member_id)
    });

    if !member_exists {
        return Err(Error::NotFound {
            msg: "Member not found".to_string(),
        });
    }

    // Ensure that the member is not already in the group
    let member = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, member)| member.id == payload.member_id)
            .unwrap()
            .1
            .clone()
    });

    let group = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, group)| group.id == payload.group_id)
            .unwrap()
            .1
            .clone()
    });

    let member_in_group = group.members.iter().any(|id| id == &member.id.to_string());

    if member_in_group {
        return Err(Error::AlreadyExists {
            msg: "Member already in the group".to_string(),
        });
    }

    // Ensure the admin exists
    let group = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, group)| group.id == payload.group_id)
            .unwrap()
            .1
            .clone()
    });

    let admin_exists = ADMIN_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.id.to_string() == group.admin_id)
    });

    if !admin_exists {
        return Err(Error::UnAuthorized {
            msg: "Unauthorized access".to_string(),
        });
    }

    // Add the member to the group
    let member = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, member)| member.id == payload.member_id)
            .unwrap()
            .1
            .clone()
    });

    let mut group = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, group)| group.id == payload.group_id)
            .unwrap()
            .1
            .clone()
    });

    group.members.push(member.id.to_string());
    GROUPS_STORAGE.with(|storage| storage.borrow_mut().insert(group.id, group.clone()));
    Ok(member)
}

// Adds a new contribution with the provided payload and awards points
#[ic_cdk::update]
fn add_contribution(payload: ContributionPayload) -> Result<Contribution, Error> {
    if payload.amount <= 0.0 {
        return Err(Error::EmptyFields {
            msg: "Amount must be greater than zero".to_string(),
        });
    }

    // Ensure that the group exists
    let group_exists = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, group)| group.id == payload.group_id)
    });

    if !group_exists {
        return Err(Error::NotFound {
            msg: "Group not found".to_string(),
        });
    }

    // Ensure that the member exists
    let member_exists = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, member)| member.id == payload.member_id)
    });

    if !member_exists {
        return Err(Error::NotFound {
            msg: "Member not found".to_string(),
        });
    }

    let id = ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    });

    let contribution = Contribution {
        id,
        group_id: payload.group_id,
        member_id: payload.member_id,
        amount: payload.amount,
        created_at: get_current_time(),
    };

    // Award points to the member based on the contribution amount
    let _member = MEMBERS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        let member = storage
            .iter()
            .find(|(_, member)| member.id == payload.member_id)
            .unwrap()
            .1
            .clone();

        let updated_member = Member {
            id: member.id,
            name: member.name,
            email: member.email,
            points: member.points + (payload.amount as u64),
            created_at: member.created_at,
        };

        storage.insert(member.id, updated_member.clone());
        updated_member
    });

    CONTRIBUTIONS_STORAGE.with(|storage| storage.borrow_mut().insert(id, contribution.clone()));
    Ok(contribution)
}

// Function to create a new proposal
#[ic_cdk::update]
fn create_proposal(payload: ProposalPayload) -> Result<Proposal, Error> {
    if payload.description.is_empty() {
        return Err(Error::EmptyFields {
            msg: "Description is required".to_string(),
        });
    }

    // Ensure that the group exists
    let group_exists = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, group)| group.id == payload.group_id)
    });

    if !group_exists {
        return Err(Error::NotFound {
            msg: "Group not found".to_string(),
        });
    }

    // Ensure that the proposer is a member of the group
    let member_exists = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, group)| group.id == payload.group_id && group.members.contains(&payload.proposer_id.to_string()))
    });

    if !member_exists {
        return Err(Error::NotGroupMember {
            msg: "Proposer is not a member of the group".to_string(),
        });
    }

    let id = ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    });

    let proposal = Proposal {
        id,
        group_id: payload.group_id,
        proposer_id: payload.proposer_id,
        description: payload.description,
        votes_for: 0,
        votes_against: 0,
        created_at: get_current_time(),
    };

    PROPOSALS_STORAGE.with(|storage| storage.borrow_mut().insert(id, proposal.clone()));
    Ok(proposal)
}

// Function to vote on a proposal
#[ic_cdk::update]
fn vote_proposal(payload: VotePayload) -> Result<Proposal, Error> {
    // Ensure that the proposal exists
    let proposal_exists = PROPOSALS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, proposal)| proposal.id == payload.proposal_id)
    });

    if !proposal_exists {
        return Err(Error::NotFound {
            msg: "Proposal not found".to_string(),
        });
    }

    // Ensure that the member exists
    let member_exists = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, member)| member.id == payload.member_id)
    });

    if !member_exists {
        return Err(Error::NotFound {
            msg: "Member not found".to_string(),
        });
    }

    // Ensure that the member is a member of the group
    let proposal = PROPOSALS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.proposal_id)
            .unwrap()
            .clone()
    });

    let member_in_group = GROUPS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, group)| group.id == proposal.group_id && group.members.contains(&payload.member_id.to_string()))
    });

    if !member_in_group {
        return Err(Error::NotGroupMember {
            msg: "Member is not a member of the group".to_string(),
        });
    }
    
    // Record the vote
    let proposal = PROPOSALS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        let proposal = storage
            .iter()
            .find(|(_, proposal)| proposal.id == payload.proposal_id)
            .unwrap()
            .1
            .clone();

        let updated_proposal = if payload.vote {
            Proposal {
                id: proposal.id,
                group_id: proposal.group_id,
                proposer_id: proposal.proposer_id,
                description: proposal.description,
                votes_for: proposal.votes_for + 1,
                votes_against: proposal.votes_against,
                created_at: proposal.created_at,
            }
        } else {
            Proposal {
                id: proposal.id,
                group_id: proposal.group_id,
                proposer_id: proposal.proposer_id,
                description: proposal.description,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against + 1,
                created_at: proposal.created_at,
            }
        };

        storage.insert(proposal.id, updated_proposal.clone());
        updated_proposal
    });

    Ok(proposal)
}

// Retrieves all contributions for a group
#[ic_cdk::query]
fn get_group_contributions(group_id: u64) -> Result<Vec<Contribution>, Error> {
    CONTRIBUTIONS_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let contributions = storage
            .iter()
            .filter(|(_, contribution)| contribution.group_id == group_id)
            .map(|(_, contribution)| contribution.clone())
            .collect::<Vec<Contribution>>();

        if contributions.is_empty() {
            Err(Error::NotFound {
                msg: "No contributions found".to_string(),
            })
        } else {
            Ok(contributions)
        }
    })
}

// Retrieves the leaderboard
#[ic_cdk::query]
fn get_leaderboard() -> Vec<Member> {
    let mut members: Vec<Member> = MEMBERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, member)| member.clone())
            .collect()
    });

    // Sort members by points in descending order
    members.sort_by(|a, b| b.points.cmp(&a.points));
    members
}

// Retrieves all proposals for a group
#[ic_cdk::query]
fn get_group_proposals(group_id: u64) -> Result<Vec<Proposal>, Error> {
    PROPOSALS_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let proposals = storage
            .iter()
            .filter(|(_, proposal)| proposal.group_id == group_id)
            .map(|(_, proposal)| proposal.clone())
            .collect::<Vec<Proposal>>();

        if proposals.is_empty() {
            Err(Error::NotFound {
                msg: "No proposals found".to_string(),
            })
        } else {
            Ok(proposals)
        }
    })
}

// Function to remove a group by its ID
#[ic_cdk::update]
fn remove_group(group_id: u64) -> Result<(), Error> {
    GROUPS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&group_id).is_none() {
            return Err(Error::NotFound {
                msg: "Group not found".to_string(),
            });
        }
        Ok(())
    })
}

// Function to update points for a member
#[ic_cdk::update]
fn update_member_points(member_id: u64, points: u64) -> Result<Member, Error> {
    MEMBERS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        let member = storage.get(&member_id).ok_or_else(|| Error::NotFound {
            msg: "Member not found".to_string(),
        })?;
        let updated_member = Member {
            id: member.id,
            name: member.name,
            email: member.email,
            points,
            created_at: member.created_at,
        };
        storage.insert(member.id, updated_member.clone());
        Ok(updated_member)
    })
}

// Function to get the current time in nanoseconds since the Unix epoch
fn get_current_time() -> u64 {
    time() / 1_000_000 // Convert to milliseconds
}

// Export the candid interface
ic_cdk::export_candid!();