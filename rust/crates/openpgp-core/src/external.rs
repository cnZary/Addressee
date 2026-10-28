use pgp::{
    composed::{KeyType, SecretKeyParamsBuilder, SignedPublicSubKey, SignedSecretKey},
    crypto::{ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm},
    packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{
        EcdhPublicParams, EcdsaPublicParams, KeyDetails as _, Password, PublicParams, S2kParams,
        Timestamp,
    },
};
use rand::{Rng as _, distributions::Alphanumeric};
use zeroize::Zeroizing;

use crate::{GeneratedKey, KeyError, P256RemoteKey, PrivateExportPolicy, SoftwareKeyStore};

impl SoftwareKeyStore {
    pub fn generate_external_p256(
        &mut self,
        user_id: &str,
        signing: &P256RemoteKey,
        encryption: &P256RemoteKey,
    ) -> Result<GeneratedKey, KeyError> {
        if user_id.is_empty() {
            return Err(KeyError::EmptyUserId);
        }
        if signing.reference() == encryption.reference() {
            return Err(KeyError::InvalidParameters(
                "signing and encryption require distinct hardware key references".to_owned(),
            ));
        }
        let signing_public = signing.public_subkey()?;
        let encryption_public = encryption.public_subkey()?;
        if !matches!(
            signing_public.public_params(),
            PublicParams::ECDSA(EcdsaPublicParams::P256 { .. })
        ) || signing_public.algorithm() != PublicKeyAlgorithm::ECDSA
            || !matches!(
                encryption_public.public_params(),
                PublicParams::ECDH(EcdhPublicParams::P256 { .. })
            )
            || encryption_public.algorithm() != PublicKeyAlgorithm::ECDH
        {
            return Err(KeyError::InvalidParameters(
                "external generation requires a P-256 signing and an ECDH component".to_owned(),
            ));
        }

        let mut rng = rand::thread_rng();
        let protection_password = Zeroizing::new(
            (&mut rng)
                .sample_iter(Alphanumeric)
                .take(64)
                .map(char::from)
                .collect::<String>(),
        );
        let version = pgp::types::KeyVersion::V4;
        let params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::ECDSA(ECCCurve::P256))
            .can_certify(true)
            .can_sign(false)
            .primary_user_id(user_id.to_owned())
            .feature_seipd_v2(false)
            .passphrase(Some(protection_password.as_str().to_owned()))
            .s2k(Some(S2kParams::new_default(&mut rng, version)))
            .subkeys(Vec::new())
            .build()
            .map_err(|error| KeyError::InvalidParameters(error.to_string()))?;
        let primary = params.generate(&mut rng)?;

        let mut back_config =
            SignatureConfig::from_key(&mut rng, signing, SignatureType::KeyBinding)?;
        back_config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signing.fingerprint()))?,
        ];
        back_config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            signing.legacy_key_id(),
        ))?];
        let back_signature = back_config.sign_primary_key_binding(
            signing,
            signing.public_key(),
            &Password::empty(),
            primary.primary_key.public_key(),
        )?;

        let mut signing_flags = KeyFlags::default();
        signing_flags.set_sign(true);
        let signing_binding = signing_public.sign(
            &mut rng,
            &primary.primary_key,
            primary.primary_key.public_key(),
            &Password::from(protection_password.as_str()),
            signing_flags,
            Some(back_signature),
        )?;
        let signing_subkey = SignedPublicSubKey::new(signing_public, vec![signing_binding]);

        let mut encryption_flags = KeyFlags::default();
        encryption_flags.set_encrypt_comms(true);
        encryption_flags.set_encrypt_storage(true);
        let encryption_binding = encryption_public.sign(
            &mut rng,
            &primary.primary_key,
            primary.primary_key.public_key(),
            &Password::from(protection_password.as_str()),
            encryption_flags,
            None,
        )?;
        let encryption_subkey =
            SignedPublicSubKey::new(encryption_public, vec![encryption_binding]);
        let secret = SignedSecretKey::new(
            primary.primary_key,
            primary.details,
            vec![signing_subkey, encryption_subkey],
            Vec::new(),
        );
        self.insert_external_certificate(secret, PrivateExportPolicy::Disabled)
    }
}
