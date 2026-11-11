//! NEP-297 audit events for the skjold registry.
//!
//! Every event carries the `skjold-registry` standard and version `1.0.0`. The
//! `#[near(event_json(...))]` attribute derives the NEP-297 envelope and the
//! `EventMetadata` implementation used to emit events.

use near_sdk::near;

use crate::types::{
    AgentRevoked, AnchorData, CredData, CredentialRevoked, DelegData, DelegationRevoked,
    IdentityData, InteractionData, TeeData,
};

#[near(event_json(standard = "skjold-registry"))]
pub enum Event {
    #[event_version("1.0.0")]
    IdentityCreated(Vec<IdentityData>),
    #[event_version("1.0.0")]
    IdentityRevoked(Vec<AgentRevoked>),
    #[event_version("1.0.0")]
    CredentialAnchored(Vec<CredData>),
    #[event_version("1.0.0")]
    CredentialRevoked(Vec<CredentialRevoked>),
    #[event_version("1.0.0")]
    DelegationRecorded(Vec<DelegData>),
    #[event_version("1.0.0")]
    DelegationRevoked(Vec<DelegationRevoked>),
    #[event_version("1.0.0")]
    InteractionRecorded(Vec<InteractionData>),
    #[event_version("1.0.0")]
    TeeAttestationBound(Vec<TeeData>),
    #[event_version("1.0.0")]
    ArtifactAnchored(Vec<AnchorData>),
}
