#![forbid(unsafe_code)]

//! Identify by certificate: the peer certificate's subject, read off the
//! connection and not verified.
//!
//! A TLS handshake that asked for a client certificate leaves the transport
//! knowing who the peer said it was. This identifier reads that and calls it
//! the claim: the subject distinguished name is the value, the issuer and the
//! fingerprint ride beside it as evidence, and the chain the peer sent, where
//! the transport kept it, rides as proof for the second gate. Whether that
//! chain reaches a trust anchor is `authenticate/certificate`'s question, and
//! nothing here answers it.
//!
//! The transport vocabulary this reads, promoted onto the arrival by any
//! transport that terminates TLS:
//!
//! ```text
//! tls.peer.subject       CN=partner-x.example,O=Partner X   the claim
//! tls.peer.issuer        CN=Partner CA,O=Partner X          evidence
//! tls.peer.fingerprint   SHA256:ab12…                        evidence
//! tls.peer.upn           jane@partner-x.example              evidence principal.user
//! tls.peer.chain        PEM, leaf first                     proof certificate.chain
//! tls.peer.verified      verified                            proof mutual-tls.handshake
//! ```
//!
//! Two mechanisms come off this one reading, because only the transport
//! knows which it is: where the handshake itself verified the chain the
//! transport says so in `tls.peer.verified`, the claim is `mutual-tls` and
//! its proof is the transport's word; where the certificate merely arrived,
//! the claim is `certificate` and its proof is the chain for the second gate
//! to walk (ADR-0033 clause 1, amended 2026-09-18).
//!
//! A smart-card certificate carries a user principal name as a subjectAltName
//! otherName, OID 1.3.6.1.4.1.311.20.2.3. This crate parses no X.509: the
//! transport that does promotes the name as `tls.peer.upn`, and where that is
//! a user principal name it is written as `principal.user` in the
//! capability's canonical form, beside the subject, which stays the value
//! (ADR-0054). Where it is absent, or is not one, nothing is added.
//!
//! Only a pushed arrival carries a passed claim. Where Xmip went and fetched
//! the Stream, or found it waiting, the certificate in play was Xmip's own and
//! says nothing about the source.

use identify::{
    IdentifyError, Presented, StreamArrival, TransportIdentifier, UserPrincipalName, principal,
};
use xcore::{Arriving, Mechanism};

/// The property carrying the user principal name a smart-card certificate
/// holds as a subjectAltName otherName, OID 1.3.6.1.4.1.311.20.2.3, read out
/// by the transport.
pub const UPN: &str = "tls.peer.upn";

/// The property carrying the subject distinguished name.
pub const SUBJECT: &str = "tls.peer.subject";
/// The property carrying the issuer distinguished name.
pub const ISSUER: &str = "tls.peer.issuer";
/// The property carrying the certificate's fingerprint, `SHA256:` first.
pub const FINGERPRINT: &str = "tls.peer.fingerprint";
/// The property carrying the chain the peer sent, as PEM, leaf first.
pub const CHAIN: &str = "tls.peer.chain";
/// The proof name the chain rides under, read by `authenticate/certificate`.
pub const CHAIN_PROOF: &str = "certificate.chain";

/// The property the transport promotes when its handshake verified the chain.
pub const VERIFIED: &str = "tls.peer.verified";

/// The proof name the transport's word rides under, read by
/// `authenticate/mutual-tls`.
pub const HANDSHAKE_PROOF: &str = "mutual-tls.handshake";

const PEM_HEADER: &str = "-----BEGIN CERTIFICATE-----";

/// Reads the peer certificate the transport reported.
#[derive(Clone, Copy, Debug, Default)]
pub struct Certificate;

impl TransportIdentifier for Certificate {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::certificate()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let subject = match arrival.property(SUBJECT) {
            Some(subject) => subject.trim(),
            None if [ISSUER, FINGERPRINT, CHAIN, UPN]
                .iter()
                .any(|name| arrival.property(name).is_some()) =>
            {
                return Err(IdentifyError::new(
                    "the transport reported a peer certificate without its subject",
                ));
            }
            None => return Ok(None),
        };
        if subject.is_empty() {
            return Err(IdentifyError::new(
                "the peer certificate's subject is empty",
            ));
        }

        let handshake = arrival.property(VERIFIED).map(str::trim);
        let mechanism = match handshake {
            Some(_) => xcore::mechanism::mutual_tls(),
            None => self.mechanism(),
        };
        let mut claim = Presented::passed(mechanism, subject);
        if let Some(word) = handshake {
            claim = claim.with_proof(HANDSHAKE_PROOF, word);
        }
        if let Some(issuer) = arrival.property(ISSUER) {
            claim = claim.with_evidence(ISSUER, issuer.trim());
        }
        if let Some(fingerprint) = arrival.property(FINGERPRINT) {
            claim = claim.with_evidence(FINGERPRINT, fingerprint.trim());
        }
        if let Some(name) = arrival.property(UPN).and_then(UserPrincipalName::parse) {
            claim = claim.with_evidence(principal::USER, name.to_string());
        }
        if let Some(chain) = arrival.property(CHAIN) {
            if !chain.contains(PEM_HEADER) {
                return Err(IdentifyError::new(
                    "the peer certificate chain is not PEM: no CERTIFICATE block",
                ));
            }
            claim = claim.with_proof(CHAIN_PROOF, chain);
        }

        Ok(Some(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    const CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn properties(with_chain: bool) -> Vec<(String, String)> {
        let mut properties = vec![
            (SUBJECT.to_string(), "CN=partner-x.example".to_string()),
            (ISSUER.to_string(), "CN=Partner CA".to_string()),
            (FINGERPRINT.to_string(), "SHA256:ab12".to_string()),
        ];
        if with_chain {
            properties.push((CHAIN.to_string(), CHAIN_PEM.to_string()));
        }
        properties
    }

    #[test]
    fn a_peer_certificate_is_presented_by_its_subject_with_issuer_and_fingerprint_beside() {
        let stream = stream();
        let properties = properties(false);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Certificate
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "CN=partner-x.example");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "certificate");
        assert!(
            claim
                .evidence
                .contains(&(ISSUER.to_string(), "CN=Partner CA".to_string()))
        );
        assert!(
            claim
                .evidence
                .contains(&(FINGERPRINT.to_string(), "SHA256:ab12".to_string()))
        );
    }

    #[test]
    fn the_chain_rides_as_proof_and_never_as_evidence() {
        let stream = stream();
        let properties = properties(true);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Certificate
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.proof(CHAIN_PROOF), Some(CHAIN_PEM));
        assert!(claim.evidence.iter().all(|(name, _)| name != CHAIN));
    }

    #[test]
    fn a_chain_the_handshake_verified_is_mutual_tls_with_the_transports_word_as_proof() {
        let stream = stream();
        let mut properties = properties(true);
        properties.push((VERIFIED.to_string(), "verified".to_string()));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Certificate
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "mutual-tls");
        assert_eq!(claim.value, "CN=partner-x.example");
        assert_eq!(claim.proof(HANDSHAKE_PROOF), Some("verified"));
        assert_eq!(claim.proof(CHAIN_PROOF), Some(CHAIN_PEM));
    }

    #[test]
    fn a_smart_card_certificates_principal_name_is_written_in_canonical_form() {
        let stream = stream();
        let mut properties = properties(false);
        properties.push((UPN.to_string(), "Jane@Partner-X.Example".to_string()));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Certificate
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "CN=partner-x.example", "the subject stands");
        assert!(claim.evidence.contains(&(
            principal::USER.to_string(),
            "Jane@partner-x.example".to_string()
        )));
    }

    #[test]
    fn an_alternative_name_that_is_not_a_principal_name_and_a_subject_add_no_such_evidence() {
        let stream = stream();
        let plain = properties(false);
        let mut bare = properties(false);
        bare.push((UPN.to_string(), "jane".to_string()));

        for properties in [plain, bare] {
            let arrival =
                StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

            let claim = Certificate
                .identify(&arrival)
                .expect("read")
                .expect("a claim");

            assert!(
                claim
                    .evidence
                    .iter()
                    .all(|(name, _)| name != principal::USER)
            );
        }
    }

    #[test]
    fn an_arrival_without_a_peer_certificate_presents_nothing() {
        let stream = stream();
        let properties = [("http.header.host".to_string(), "x".to_string())];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        assert!(Certificate.identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn a_chain_that_is_not_pem_is_an_error_naming_why() {
        let stream = stream();
        let mut properties = properties(false);
        properties.push((CHAIN.to_string(), "MIIB".to_string()));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Certificate.identify(&arrival).expect_err("not PEM");

        assert!(failure.message.contains("not PEM"), "{failure}");
    }

    #[test]
    fn a_certificate_reported_without_its_subject_is_an_error_and_not_an_absence() {
        let stream = stream();
        let properties = [(FINGERPRINT.to_string(), "SHA256:ab12".to_string())];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Certificate.identify(&arrival).expect_err("no subject");

        assert!(failure.message.contains("without its subject"), "{failure}");
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_certificate_was_xmips_own() {
        let stream = stream();
        let properties = properties(true);
        let arrival = StreamArrival::new(
            &stream,
            Arriving::Scheduled,
            "sftp://partner/out",
            &properties,
        );

        assert!(Certificate.identify(&arrival).expect("read").is_none());
    }
}
