use crate::types::{
    Bytes32, ConsensusError, GenericUpdate, Header, LightClientStore, SyncAggregate, SyncCommittee,
    U64,
};
use crate::utils::{calc_sync_period, is_proof_valid};
use eyre::Result;
use ssz_rs::prelude::*;
use milagro_bls::*;
// pub fn bootstrap_from(checkpoint: &[u8], bootstrap: &mut Bootstrap) -> Result<()> {
//     let is_valid = self.is_valid_checkpoint(bootstrap.header.slot.into());

//     if !is_valid {
//         if self.config.strict_scheckpoint_age {
//             return Err(ConsensusError::CheckpointTooOld.into());
//         } else {
//             warn!(target: "helios::consensus", "checkpoint too old, consider using a more recent block");
//         }
//     }

//     let committee_valid = is_current_committee_proof_valid(
//         &bootstrap.header,
//         &mut bootstrap.current_sync_committee,
//         &bootstrap.current_sync_committee_branch,
//     );

//     let header_hash = bootstrap.header.hash_tree_root()?.to_string();
//     let expected_hash = format!("0x{}", hex::encode(checkpoint));
//     let header_valid = header_hash == expected_hash;

//     if !header_valid {
//         return Err(ConsensusError::InvalidHeaderHash(expected_hash, header_hash).into());
//     }

//     if !committee_valid {
//         return Err(ConsensusError::InvalidCurrentSyncCommitteeProof.into());
//     }

//     self.store = LightClientStore {
//         finalized_header: bootstrap.header.clone(),
//         current_sync_committee: bootstrap.current_sync_committee.clone(),
//         next_sync_committee: None,
//         optimistic_header: bootstrap.header.clone(),
//         previous_max_active_participants: 0,
//         current_max_active_participants: 0,
//     };

//     Ok(())
// }
pub fn get_participating_keys(
    committee: &SyncCommittee,
    bitfield: &Bitvector<512>,
) -> Result<Vec<PublicKey>> {
    let mut pks: Vec<PublicKey> = Vec::new();
    bitfield.iter().enumerate().for_each(|(i, bit)| {
        if bit == true {
            let pk = &committee.pubkeys[i];
            let pk = PublicKey::from_bytes_unchecked(pk).unwrap();
            pks.push(pk);
        }
    });

    Ok(pks)
}

pub fn get_bits(bitfield: &Bitvector<512>) -> u64 {
    let mut count = 0;
    bitfield.iter().for_each(|bit| {
        if bit == true {
            count += 1;
        }
    });

    count
}

pub fn is_finality_proof_valid(
    attested_header: &Header,
    finality_header: &mut Header,
    finality_branch: &[Bytes32],
) -> bool {
    is_proof_valid(attested_header, finality_header, finality_branch, 6, 41)
}

pub fn is_next_committee_proof_valid(
    attested_header: &Header,
    next_committee: &mut SyncCommittee,
    next_committee_branch: &[Bytes32],
) -> bool {
    is_proof_valid(
        attested_header,
        next_committee,
        next_committee_branch,
        5,
        23,
    )
}

pub fn is_current_committee_proof_valid(
    attested_header: &Header,
    current_committee: &mut SyncCommittee,
    current_committee_branch: &[Bytes32],
) -> bool {
    is_proof_valid(
        attested_header,
        current_committee,
        current_committee_branch,
        5,
        22,
    )
}

// implements checks from validate_light_client_update and process_light_client_update in the
// specification
pub fn verify_generic_update(update: &GenericUpdate) -> Result<()> {
    let bits = get_bits(&update.sync_aggregate.sync_committee_bits);
    if bits == 0 {
        return Err(ConsensusError::InsufficientParticipation.into());
    }

    let update_finalized_slot = update.finalized_header.clone().unwrap_or_default().slot;
    let valid_time = self.expected_current_slot() >= update.signature_slot
        && update.signature_slot > update.attested_header.slot.as_u64()
        && update.attested_header.slot >= update_finalized_slot;

    if !valid_time {
        return Err(ConsensusError::InvalidTimestamp.into());
    }

    let store_period = calc_sync_period(self.store.finalized_header.slot.into());
    let update_sig_period = calc_sync_period(update.signature_slot);
    let valid_period = if self.store.next_sync_committee.is_some() {
        update_sig_period == store_period || update_sig_period == store_period + 1
    } else {
        update_sig_period == store_period
    };

    if !valid_period {
        return Err(ConsensusError::InvalidPeriod.into());
    }

    let update_attested_period = calc_sync_period(update.attested_header.slot.into());
    let update_has_next_committee = self.store.next_sync_committee.is_none()
        && update.next_sync_committee.is_some()
        && update_attested_period == store_period;

    if update.attested_header.slot <= self.store.finalized_header.slot && !update_has_next_committee
    {
        return Err(ConsensusError::NotRelevant.into());
    }

    if update.finalized_header.is_some() && update.finality_branch.is_some() {
        let is_valid = is_finality_proof_valid(
            &update.attested_header,
            &mut update.finalized_header.clone().unwrap(),
            &update.finality_branch.clone().unwrap(),
        );

        if !is_valid {
            return Err(ConsensusError::InvalidFinalityProof.into());
        }
    }

    if update.next_sync_committee.is_some() && update.next_sync_committee_branch.is_some() {
        let is_valid = is_next_committee_proof_valid(
            &update.attested_header,
            &mut update.next_sync_committee.clone().unwrap(),
            &update.next_sync_committee_branch.clone().unwrap(),
        );

        if !is_valid {
            return Err(ConsensusError::InvalidNextSyncCommitteeProof.into());
        }
    }

    let sync_committee = if update_sig_period == store_period {
        &self.store.current_sync_committee
    } else {
        self.store.next_sync_committee.as_ref().unwrap()
    };

    let pks = get_participating_keys(sync_committee, &update.sync_aggregate.sync_committee_bits)?;

    let is_valid_sig = self.verify_sync_committee_signture(
        &pks,
        &update.attested_header,
        &update.sync_aggregate.sync_committee_signature,
        update.signature_slot,
    );

    if !is_valid_sig {
        return Err(ConsensusError::InvalidSignature.into());
    }

    Ok(())
}
