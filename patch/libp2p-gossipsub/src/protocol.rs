// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::config::ValidationMode;
use crate::handler::HandlerEvent;
use crate::rpc_proto::proto;
use crate::topic::TopicHash;
use crate::types::{
    ControlAction, MessageId, PeerInfo, PeerKind, RawMessage, Rpc, RpcOut, Subscription,
    SubscriptionAction,
};
use crate::ValidationError;
use asynchronous_codec::{Decoder, Encoder, Framed};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_identity::{PeerId, PublicKey};
use libp2p_swarm::StreamProtocol;
use quick_protobuf::sizeofs::sizeof_len;
use quick_protobuf::{MessageWrite, Writer};
use smallvec::{smallvec, SmallVec};
use std::pin::Pin;
use void::Void;

pub(crate) const SIGNING_PREFIX: &[u8] = b"libp2p-pubsub:";

pub(crate) const GOSSIPSUB_1_1_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.1.0"),
    kind: PeerKind::Gossipsubv1_1,
};
pub(crate) const GOSSIPSUB_1_0_0_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/meshsub/1.0.0"),
    kind: PeerKind::Gossipsub,
};
pub(crate) const FLOODSUB_PROTOCOL: ProtocolId = ProtocolId {
    protocol: StreamProtocol::new("/floodsub/1.0.0"),
    kind: PeerKind::Floodsub,
};

/// Implementation of [`InboundUpgrade`] and [`OutboundUpgrade`] for the Gossipsub protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// The Gossipsub protocol id to listen on.
    pub(crate) protocol_ids: Vec<ProtocolId>,
    /// The maximum transmit size for a packet.
    pub(crate) max_transmit_size: usize,
    /// Determines the level of validation to be done on incoming messages.
    pub(crate) validation_mode: ValidationMode,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            max_transmit_size: 65536,
            validation_mode: ValidationMode::Strict,
            protocol_ids: vec![GOSSIPSUB_1_1_0_PROTOCOL, GOSSIPSUB_1_0_0_PROTOCOL],
        }
    }
}

/// The protocol ID
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolId {
    /// The RPC message type/name.
    pub protocol: StreamProtocol,
    /// The type of protocol we support
    pub kind: PeerKind,
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        self.protocol.as_ref()
    }
}

impl UpgradeInfo for ProtocolConfig {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocol_ids.clone()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (Framed<TSocket, GossipsubCodec>, PeerKind);
    type Error = Void;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((
            Framed::new(
                socket,
                GossipsubCodec::new(self.max_transmit_size, self.validation_mode),
            ),
            protocol_id.kind,
        )))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncWrite + AsyncRead + Unpin + Send + 'static,
{
    /// The substream is only written to, with frames from [`encode_frame`], so it isn't framed.
    type Output = (TSocket, PeerKind);
    type Error = Void;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        Box::pin(future::ok((socket, protocol_id.kind)))
    }
}

/* Gossip codec for the framing */

pub struct GossipsubCodec {
    /// Determines the level of validation performed on incoming messages.
    validation_mode: ValidationMode,
    /// The codec to handle common encoding/decoding of protobuf messages
    codec: quick_protobuf_codec::Codec<proto::RPC>,
}

impl GossipsubCodec {
    pub fn new(max_length: usize, validation_mode: ValidationMode) -> GossipsubCodec {
        let codec = quick_protobuf_codec::Codec::new(max_length);
        GossipsubCodec {
            validation_mode,
            codec,
        }
    }

    /// Verifies a gossipsub message. This returns either a success or failure. All errors
    /// are logged, which prevents error handling in the codec and handler. We simply drop invalid
    /// messages and log warnings, rather than propagating errors through the codec.
    fn verify_signature(message: &proto::Message) -> bool {
        use quick_protobuf::MessageWrite;

        let Some(from) = message.from.as_ref() else {
            tracing::debug!("Signature verification failed: No source id given");
            return false;
        };

        let Ok(source) = PeerId::from_bytes(from) else {
            tracing::debug!("Signature verification failed: Invalid Peer Id");
            return false;
        };

        let Some(signature) = message.signature.as_ref() else {
            tracing::debug!("Signature verification failed: No signature provided");
            return false;
        };

        // If there is a key value in the protobuf, use that key otherwise the key must be
        // obtained from the inlined source peer_id.
        let public_key = match message.key.as_deref().map(PublicKey::try_decode_protobuf) {
            Some(Ok(key)) => key,
            _ => match PublicKey::try_decode_protobuf(&source.to_bytes()[2..]) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("Signature verification failed: No valid public key supplied");
                    return false;
                }
            },
        };

        // The key must match the peer_id
        if source != public_key.to_peer_id() {
            tracing::warn!(
                "Signature verification failed: Public key doesn't match source peer id"
            );
            return false;
        }

        // Construct the signature bytes
        let mut message_sig = message.clone();
        message_sig.signature = None;
        message_sig.key = None;
        let mut buf = Vec::with_capacity(message_sig.get_size());
        let mut writer = Writer::new(&mut buf);
        message_sig
            .write_message(&mut writer)
            .expect("Encoding to succeed");
        let mut signature_bytes = SIGNING_PREFIX.to_vec();
        signature_bytes.extend_from_slice(&buf);
        public_key.verify(&signature_bytes, signature)
    }
}

/// A frame of the gossipsub protocol, as chunks to be written to the substream in order.
pub(crate) type Frame = SmallVec<[Bytes; 3]>;

/// Encodes `rpc` as a frame of the gossipsub protocol: the length of the RPC as an unsigned
/// varint, then the RPC, as [`GossipsubCodec`] encodes it.
///
/// A message that is published or forwarded is encoded around its data instead of copying it, so
/// the frames that send a message to each peer all share its data.
pub(crate) fn encode_frame(rpc: RpcOut) -> Frame {
    let message = match rpc {
        RpcOut::Publish(message) | RpcOut::Forward(message) => message,
        rpc => {
            let mut frame = BytesMut::new();
            quick_protobuf_codec::Codec::<proto::RPC>::new(usize::MAX)
                .encode(rpc.into_protobuf(), &mut frame)
                .expect("Encoding to succeed");
            return smallvec![frame.freeze()];
        }
    };

    // `data` is the second field of `proto::Message`: the source comes before it and the other
    // fields after it.
    let from = message.source.map(|m| m.to_bytes());
    let after_data = proto::Message {
        from: None,
        data: None,
        seqno: message.sequence_number.map(|s| s.to_be_bytes().to_vec()),
        topic: TopicHash::into_string(message.topic),
        signature: message.signature,
        key: message.key,
    };
    let message_len = from.as_ref().map_or(0, |from| 1 + sizeof_len(from.len()))
        + 1
        + sizeof_len(message.data.len())
        + after_data.get_size();

    // The frame's length, the RPC's `publish` field holding the message, then the message up to
    // its data.
    let mut head = Vec::new();
    let mut writer = Writer::new(&mut head);
    writer
        .write_varint((1 + sizeof_len(message_len)) as u64)
        .and_then(|()| writer.write_tag(18))
        .and_then(|()| writer.write_varint(message_len as u64))
        .and_then(|()| match &from {
            Some(from) => writer.write_with_tag(10, |w| w.write_bytes(from)),
            None => Ok(()),
        })
        .and_then(|()| writer.write_tag(18))
        .and_then(|()| writer.write_varint(message.data.len() as u64))
        .expect("Encoding to succeed");

    let mut tail = Vec::with_capacity(after_data.get_size());
    after_data
        .write_message(&mut Writer::new(&mut tail))
        .expect("Encoding to succeed");

    smallvec![head.into(), message.data, tail.into()]
}

impl Encoder for GossipsubCodec {
    type Item<'a> = proto::RPC;
    type Error = quick_protobuf_codec::Error;

    fn encode(&mut self, item: Self::Item<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.codec.encode(item, dst)
    }
}

impl Decoder for GossipsubCodec {
    type Item = HandlerEvent;
    type Error = quick_protobuf_codec::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(rpc) = self.codec.decode(src)? else {
            return Ok(None);
        };
        // Store valid messages.
        let mut messages = Vec::with_capacity(rpc.publish.len());
        // Store any invalid messages.
        let mut invalid_messages = Vec::new();

        for message in rpc.publish.into_iter() {
            // Keep track of the type of invalid message.
            let mut invalid_kind = None;
            let mut verify_signature = false;
            let mut verify_sequence_no = false;
            let mut verify_source = false;

            match self.validation_mode {
                ValidationMode::Strict => {
                    // Validate everything
                    verify_signature = true;
                    verify_sequence_no = true;
                    verify_source = true;
                }
                ValidationMode::Permissive => {
                    // If the fields exist, validate them
                    if message.signature.is_some() {
                        verify_signature = true;
                    }
                    if message.seqno.is_some() {
                        verify_sequence_no = true;
                    }
                    if message.from.is_some() {
                        verify_source = true;
                    }
                }
                ValidationMode::Anonymous => {
                    if message.signature.is_some() {
                        tracing::warn!(
                            "Signature field was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SignaturePresent);
                    } else if message.seqno.is_some() {
                        tracing::warn!(
                            "Sequence number was non-empty and anonymous validation mode is set"
                        );
                        invalid_kind = Some(ValidationError::SequenceNumberPresent);
                    } else if message.from.is_some() {
                        tracing::warn!("Message dropped. Message source was non-empty and anonymous validation mode is set");
                        invalid_kind = Some(ValidationError::MessageSourcePresent);
                    }
                }
                ValidationMode::None => {}
            }

            // If the initial validation logic failed, add the message to invalid messages and
            // continue processing the others.
            if let Some(validation_error) = invalid_kind.take() {
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default().into(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, validation_error));
                // proceed to the next message
                continue;
            }

            // verify message signatures if required
            if verify_signature && !GossipsubCodec::verify_signature(&message) {
                tracing::warn!("Invalid signature for received message");

                // Build the invalid message (ignoring further validation of sequence number
                // and source)
                let message = RawMessage {
                    source: None, // don't bother inform the application
                    data: message.data.unwrap_or_default().into(),
                    sequence_number: None, // don't inform the application
                    topic: TopicHash::from_raw(message.topic),
                    signature: None, // don't inform the application
                    key: message.key,
                    validated: false,
                };
                invalid_messages.push((message, ValidationError::InvalidSignature));
                // proceed to the next message
                continue;
            }

            // ensure the sequence number is a u64
            let sequence_number = if verify_sequence_no {
                if let Some(seq_no) = message.seqno {
                    if seq_no.is_empty() {
                        None
                    } else if seq_no.len() != 8 {
                        tracing::debug!(
                            sequence_number=?seq_no,
                            sequence_length=%seq_no.len(),
                            "Invalid sequence number length for received message"
                        );
                        let message = RawMessage {
                            source: None, // don't bother inform the application
                            data: message.data.unwrap_or_default().into(),
                            sequence_number: None, // don't inform the application
                            topic: TopicHash::from_raw(message.topic),
                            signature: message.signature, // don't inform the application
                            key: message.key,
                            validated: false,
                        };
                        invalid_messages.push((message, ValidationError::InvalidSequenceNumber));
                        // proceed to the next message
                        continue;
                    } else {
                        // valid sequence number
                        Some(BigEndian::read_u64(&seq_no))
                    }
                } else {
                    // sequence number was not present
                    tracing::debug!("Sequence number not present but expected");
                    let message = RawMessage {
                        source: None, // don't bother inform the application
                        data: message.data.unwrap_or_default().into(),
                        sequence_number: None, // don't inform the application
                        topic: TopicHash::from_raw(message.topic),
                        signature: message.signature, // don't inform the application
                        key: message.key,
                        validated: false,
                    };
                    invalid_messages.push((message, ValidationError::EmptySequenceNumber));
                    continue;
                }
            } else {
                // Do not verify the sequence number, consider it empty
                None
            };

            // Verify the message source if required
            let source = if verify_source {
                if let Some(bytes) = message.from {
                    if !bytes.is_empty() {
                        match PeerId::from_bytes(&bytes) {
                            Ok(peer_id) => Some(peer_id), // valid peer id
                            Err(_) => {
                                // invalid peer id, add to invalid messages
                                tracing::debug!("Message source has an invalid PeerId");
                                let message = RawMessage {
                                    source: None, // don't bother inform the application
                                    data: message.data.unwrap_or_default().into(),
                                    sequence_number,
                                    topic: TopicHash::from_raw(message.topic),
                                    signature: message.signature, // don't inform the application
                                    key: message.key,
                                    validated: false,
                                };
                                invalid_messages.push((message, ValidationError::InvalidPeerId));
                                continue;
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // This message has passed all validation, add it to the validated messages.
            messages.push(RawMessage {
                source,
                data: message.data.unwrap_or_default().into(),
                sequence_number,
                topic: TopicHash::from_raw(message.topic),
                signature: message.signature,
                key: message.key,
                validated: false,
            });
        }

        let mut control_msgs = Vec::new();

        if let Some(rpc_control) = rpc.control {
            // Collect the gossipsub control messages
            let ihave_msgs: Vec<ControlAction> = rpc_control
                .ihave
                .into_iter()
                .map(|ihave| ControlAction::IHave {
                    topic_hash: TopicHash::from_raw(ihave.topic_id.unwrap_or_default()),
                    message_ids: ihave
                        .message_ids
                        .into_iter()
                        .map(MessageId::from)
                        .collect::<Vec<_>>(),
                })
                .collect();

            let iwant_msgs: Vec<ControlAction> = rpc_control
                .iwant
                .into_iter()
                .map(|iwant| ControlAction::IWant {
                    message_ids: iwant
                        .message_ids
                        .into_iter()
                        .map(MessageId::from)
                        .collect::<Vec<_>>(),
                })
                .collect();

            let graft_msgs: Vec<ControlAction> = rpc_control
                .graft
                .into_iter()
                .map(|graft| ControlAction::Graft {
                    topic_hash: TopicHash::from_raw(graft.topic_id.unwrap_or_default()),
                })
                .collect();

            let mut prune_msgs = Vec::new();

            for prune in rpc_control.prune {
                // filter out invalid peers
                let peers = prune
                    .peers
                    .into_iter()
                    .filter_map(|info| {
                        info.peer_id
                            .as_ref()
                            .and_then(|id| PeerId::from_bytes(id).ok())
                            .map(|peer_id|
                                    //TODO signedPeerRecord, see https://github.com/libp2p/specs/pull/217
                                    PeerInfo {
                                        peer_id: Some(peer_id),
                                    })
                    })
                    .collect::<Vec<PeerInfo>>();

                let topic_hash = TopicHash::from_raw(prune.topic_id.unwrap_or_default());
                prune_msgs.push(ControlAction::Prune {
                    topic_hash,
                    peers,
                    backoff: prune.backoff,
                });
            }

            control_msgs.extend(ihave_msgs);
            control_msgs.extend(iwant_msgs);
            control_msgs.extend(graft_msgs);
            control_msgs.extend(prune_msgs);
        }

        Ok(Some(HandlerEvent::Message {
            rpc: Rpc {
                messages,
                subscriptions: rpc
                    .subscriptions
                    .into_iter()
                    .map(|sub| Subscription {
                        action: if Some(true) == sub.subscribe {
                            SubscriptionAction::Subscribe
                        } else {
                            SubscriptionAction::Unsubscribe
                        },
                        topic_hash: TopicHash::from_raw(sub.topic_id.unwrap_or_default()),
                    })
                    .collect(),
                control_msgs,
            },
            invalid_messages,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{Behaviour, ConfigBuilder};
    use crate::{IdentTopic as Topic, Version};
    use libp2p_identity::Keypair;
    use quickcheck::*;

    #[derive(Clone, Debug)]
    struct Message(RawMessage);

    impl Arbitrary for Message {
        fn arbitrary(g: &mut Gen) -> Self {
            let keypair = TestKeypair::arbitrary(g);

            // generate an arbitrary GossipsubMessage using the behaviour signing functionality
            let config = Config::default();
            let mut gs: Behaviour =
                Behaviour::new(crate::MessageAuthenticity::Signed(keypair.0), config).unwrap();
            let data = (0..g.gen_range(10..10024u32))
                .map(|_| u8::arbitrary(g))
                .collect::<Vec<_>>();
            let topic_id = TopicId::arbitrary(g).0;
            Message(gs.build_raw_message(topic_id, data).unwrap())
        }
    }

    #[derive(Clone, Debug)]
    struct TopicId(TopicHash);

    impl Arbitrary for TopicId {
        fn arbitrary(g: &mut Gen) -> Self {
            let topic_string: String = (0..g.gen_range(20..1024u32))
                .map(|_| char::arbitrary(g))
                .collect::<String>();
            TopicId(Topic::new(topic_string).into())
        }
    }

    #[derive(Clone)]
    struct TestKeypair(Keypair);

    impl Arbitrary for TestKeypair {
        fn arbitrary(_g: &mut Gen) -> Self {
            // Small enough to be inlined.
            TestKeypair(Keypair::generate_ed25519())
        }
    }

    impl std::fmt::Debug for TestKeypair {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TestKeypair")
                .field("public", &self.0.public())
                .finish()
        }
    }

    #[test]
    /// Test that RPC messages can be encoded and decoded successfully.
    fn encode_decode() {
        fn prop(message: Message) {
            let message = message.0;

            let rpc = Rpc {
                messages: vec![message.clone()],
                subscriptions: vec![],
                control_msgs: vec![],
            };

            let mut codec = GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict);
            let mut buf = BytesMut::new();
            codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
            let decoded_rpc = codec.decode(&mut buf).unwrap().unwrap();
            // mark as validated as its a published message
            match decoded_rpc {
                HandlerEvent::Message { mut rpc, .. } => {
                    rpc.messages[0].validated = true;

                    assert_eq!(vec![message], rpc.messages);
                }
                _ => panic!("Must decode a message"),
            }
        }

        QuickCheck::new().quickcheck(prop as fn(_) -> _)
    }

    /// Returns the frame that [`GossipsubCodec`] encodes `rpc` into.
    fn codec_frame(rpc: RpcOut) -> Vec<u8> {
        let mut codec = GossipsubCodec::new(u32::MAX as usize, ValidationMode::Strict);
        let mut buf = BytesMut::new();
        codec.encode(rpc.into_protobuf(), &mut buf).unwrap();
        buf.to_vec()
    }

    #[test]
    /// Test that the frames written to the substream are the frames the codec encodes, and that
    /// published messages share their data with the frames.
    fn encode_frame_matches_codec() {
        fn prop(message: Message) {
            let message = message.0;
            for rpc in [
                RpcOut::Publish(message.clone()),
                RpcOut::Forward(message.clone()),
            ] {
                let frame = encode_frame(rpc.clone());
                assert_eq!(frame.concat(), codec_frame(rpc));
                assert_eq!(frame[1].as_ptr(), message.data.as_ptr());
            }
        }

        QuickCheck::new().quickcheck(prop as fn(_) -> _);

        let anonymous = RawMessage {
            source: None,
            data: Bytes::new(),
            sequence_number: None,
            topic: TopicHash::from_raw("topic"),
            signature: None,
            key: None,
            validated: true,
        };
        let large = RawMessage {
            source: Some(PeerId::random()),
            data: vec![7; 2 * 1024 * 1024].into(),
            sequence_number: Some(u64::MAX),
            key: Some(vec![1; 300]),
            signature: Some(vec![2; 200]),
            ..anonymous.clone()
        };
        for rpc in [
            RpcOut::Forward(anonymous),
            RpcOut::Publish(large),
            RpcOut::Subscribe(TopicHash::from_raw("topic")),
            RpcOut::Control(ControlAction::IWant {
                message_ids: vec![MessageId::new(b"id")],
            }),
        ] {
            assert_eq!(encode_frame(rpc.clone()).concat(), codec_frame(rpc));
        }
    }

    #[test]
    fn support_floodsub_with_custom_protocol() {
        let protocol_config = ConfigBuilder::default()
            .protocol_id("/foosub", Version::V1_1)
            .support_floodsub()
            .build()
            .unwrap()
            .protocol_config();

        assert_eq!(protocol_config.protocol_ids[0].protocol, "/foosub");
        assert_eq!(protocol_config.protocol_ids[1].protocol, "/floodsub/1.0.0");
    }
}
