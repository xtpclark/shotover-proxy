use crate::codec::postgres::PostgresCodecState;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// The startup packet length is limited to prevent unbounded allocation from garbage bytes,
/// matching the `MAX_STARTUP_PACKET_LENGTH` limit enforced by postgres itself.
const MAX_STARTUP_PACKET_LENGTH: usize = 10000;

/// Sanity cap on a single tagged message, protecting against garbage length headers.
/// Real postgres messages can approach 1GB (a single large field), so this is deliberately generous.
const MAX_MESSAGE_LENGTH: usize = 1024 * 1024 * 1024;

pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const GSSENC_REQUEST_CODE: i32 = 80877104;
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

/// A PostgreSQL protocol 3.x message as seen by transforms.
///
/// Requests hold exactly one frontend message.
/// Responses hold the complete train of backend messages that answer one request,
/// e.g. a simple `Query` response holds `RowDescription, DataRow*, CommandComplete, ReadyForQuery`.
/// Grouping the train into one frame is what upholds shotover's one-response-per-request
/// invariant on a protocol where one request produces many wire messages.
#[derive(Debug, Clone, PartialEq)]
pub enum PostgresFrame {
    Request(FrontendMessage),
    Response(Vec<BackendMessage>),
}

/// A message sent by the client.
///
/// Any tagged message that fails its typed parse degrades to [`FrontendMessage::Raw`],
/// which round-trips byte identically, so unknown or malformed messages proxy untouched.
#[derive(Debug, Clone, PartialEq)]
pub enum FrontendMessage {
    /// The untagged startup message opening a connection.
    Startup {
        /// Protocol version requested by the client, major in the high 16 bits e.g. 3.0 is 196608.
        protocol_version: i32,
        /// Startup parameters such as `user`, `database` and `_pq_.*` protocol extensions.
        parameters: Vec<(String, String)>,
    },
    /// The untagged cancel request, sent on its own dedicated connection.
    CancelRequest {
        process_id: i32,
        /// 4 bytes in protocol 3.0, variable length from protocol 3.2.
        secret_key: Bytes,
    },
    /// 'Q' - a simple query, one or more SQL statements separated by semicolons.
    Query { query: String },
    /// 'P' - extended query: parse a statement.
    Parse {
        statement_name: String,
        query: String,
        parameter_data_types: Vec<i32>,
    },
    /// 'B' - extended query: bind parameters to a parsed statement, producing a portal.
    Bind {
        portal_name: String,
        statement_name: String,
        parameter_format_codes: Vec<i16>,
        /// One entry per parameter, None encodes a NULL.
        parameter_values: Vec<Option<Bytes>>,
        result_format_codes: Vec<i16>,
    },
    /// 'D' - extended query: describe a statement (`kind` b'S') or portal (`kind` b'P').
    Describe { kind: u8, name: String },
    /// 'E' - extended query: execute a portal.
    Execute { portal_name: String, max_rows: i32 },
    /// 'S' - extended query: commit the pipeline, requesting ReadyForQuery.
    Sync,
    /// 'H' - request the server flush pending output.
    Flush,
    /// 'C' - extended query: close a statement (`kind` b'S') or portal (`kind` b'P').
    Close { kind: u8, name: String },
    /// 'd' - one chunk of COPY FROM STDIN data.
    CopyData(Bytes),
    /// 'c' - the client has finished sending COPY data.
    CopyDone,
    /// 'f' - the client failed to produce COPY data.
    CopyFail { message: String },
    /// 'p' - authentication data: PasswordMessage, SASLInitialResponse, SASLResponse or GSS bytes.
    /// Kept opaque because its layout depends on authentication state, and shotover never needs
    /// to inspect it to proxy it.
    AuthenticationData(Bytes),
    /// 'X' - the client is closing the connection.
    Terminate,
    /// Any tagged message shotover does not model, kept byte identical.
    Raw { tag: u8, body: Bytes },
}

/// A message sent by the server.
///
/// Any tagged message that fails its typed parse degrades to [`BackendMessage::Raw`],
/// which round-trips byte identically.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendMessage {
    /// 'R' - an authentication request or acknowledgement.
    Authentication(AuthenticationMessage),
    /// 'K' - cancellation key data for use in CancelRequest.
    BackendKeyData {
        process_id: i32,
        /// 4 bytes in protocol 3.0, variable length from protocol 3.2.
        secret_key: Bytes,
    },
    /// 'S' - a run-time parameter status report such as server_version or TimeZone.
    ParameterStatus { name: String, value: String },
    /// 'Z' - the server is ready for a new query.
    /// status is b'I' idle, b'T' in transaction, b'E' in failed transaction.
    ReadyForQuery { status: u8 },
    /// 'T' - the shape of the rows that will follow.
    RowDescription { fields: Vec<FieldDescription> },
    /// 'D' - one result row. One entry per column, None encodes a NULL.
    DataRow { values: Vec<Option<Bytes>> },
    /// 'C' - a statement completed, with its command tag e.g. "SELECT 5".
    CommandComplete { tag: String },
    /// 'I' - the query string was empty.
    EmptyQueryResponse,
    /// 'E' - an error. Fields are (field type byte, value) pairs, e.g. (b'C', "42P01").
    ErrorResponse { fields: Vec<(u8, String)> },
    /// 'N' - a notice. Same field layout as ErrorResponse.
    NoticeResponse { fields: Vec<(u8, String)> },
    /// '1' - a Parse message completed.
    ParseComplete,
    /// '2' - a Bind message completed.
    BindComplete,
    /// '3' - a Close message completed.
    CloseComplete,
    /// 'n' - the described statement or portal returns no rows.
    NoData,
    /// 't' - the parameter types of a described statement.
    ParameterDescription { parameter_data_types: Vec<i32> },
    /// 's' - an Execute hit its row limit, the portal is suspended.
    PortalSuspended,
    /// 'G' - the server is ready to receive COPY FROM STDIN data.
    CopyInResponse {
        overall_format: i8,
        column_formats: Vec<i16>,
    },
    /// 'H' - the server is about to send COPY TO STDOUT data.
    CopyOutResponse {
        overall_format: i8,
        column_formats: Vec<i16>,
    },
    /// 'W' - copy-both mode is starting (streaming replication).
    CopyBothResponse {
        overall_format: i8,
        column_formats: Vec<i16>,
    },
    /// 'd' - one chunk of COPY TO STDOUT data.
    CopyData(Bytes),
    /// 'c' - the server has finished sending COPY data.
    CopyDone,
    /// 'A' - a NOTIFY payload.
    NotificationResponse {
        process_id: i32,
        channel: String,
        payload: String,
    },
    /// 'v' - the server does not support the requested minor protocol version.
    NegotiateProtocolVersion {
        newest_minor_version: i32,
        unsupported_options: Vec<String>,
    },
    /// Any tagged message shotover does not model, kept byte identical.
    Raw { tag: u8, body: Bytes },
}

/// The body of an 'R' Authentication message, discriminated by its leading i32 code.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticationMessage {
    /// code 0 - authentication succeeded.
    Ok,
    /// code 3 - the server wants a cleartext password.
    CleartextPassword,
    /// code 5 - the server wants an MD5 hashed password.
    Md5Password { salt: [u8; 4] },
    /// code 10 - the server offers these SASL mechanisms, e.g. SCRAM-SHA-256.
    Sasl { mechanisms: Vec<String> },
    /// code 11 - a SASL challenge to continue the exchange.
    SaslContinue { data: Bytes },
    /// code 12 - the final SASL server message.
    SaslFinal { data: Bytes },
    /// Any other code, e.g. KerberosV5(2), GSS(7), GSSContinue(8), SSPI(9).
    Other { code: i32, data: Bytes },
}

/// One column in a RowDescription.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: i32,
    pub column_attribute_number: i16,
    pub data_type_oid: i32,
    pub data_type_size: i16,
    pub type_modifier: i32,
    /// 0 for text, 1 for binary.
    pub format_code: i16,
}

/// Returns the total wire length of the next message in `src`, or None if incomplete.
/// `startup` selects the untagged framing used before the startup message completes.
pub fn message_wire_length(src: &[u8], startup: bool) -> Result<Option<usize>> {
    if startup {
        if src.len() < 4 {
            return Ok(None);
        }
        let length = i32::from_be_bytes(src[0..4].try_into().unwrap());
        if !(8..=MAX_STARTUP_PACKET_LENGTH as i32).contains(&length) {
            return Err(anyhow!(
                "Invalid postgres startup packet length {length}, expected 8..={MAX_STARTUP_PACKET_LENGTH} (is the client speaking postgres protocol?)"
            ));
        }
        Ok(Some(length as usize))
    } else {
        if src.len() < 5 {
            return Ok(None);
        }
        let length = i32::from_be_bytes(src[1..5].try_into().unwrap());
        if !(4..=MAX_MESSAGE_LENGTH as i32).contains(&length) {
            return Err(anyhow!(
                "Invalid postgres message length {length} for tag {:?}",
                src[0] as char
            ));
        }
        Ok(Some(length as usize + 1))
    }
}

impl PostgresFrame {
    /// Parses the bytes of one shotover Message.
    /// For requests the bytes hold exactly one frontend message.
    /// For responses the bytes hold one complete train of backend messages.
    pub fn from_bytes(bytes: Bytes, state: PostgresCodecState) -> Result<PostgresFrame> {
        if state.is_request {
            let message = if state.startup {
                parse_startup_family(bytes)?
            } else {
                let (tag, body) = split_tagged_message(bytes)?;
                FrontendMessage::parse(tag, body)
            };
            Ok(PostgresFrame::Request(message))
        } else {
            let mut messages = vec![];
            let mut remaining = bytes;
            while !remaining.is_empty() {
                let length = message_wire_length(&remaining, false)?
                    .ok_or_else(|| anyhow!("Incomplete postgres message in response train"))?;
                if length > remaining.len() {
                    return Err(anyhow!("Incomplete postgres message in response train"));
                }
                let (tag, body) = split_tagged_message(remaining.split_to(length))?;
                messages.push(BackendMessage::parse(tag, body));
            }
            Ok(PostgresFrame::Response(messages))
        }
    }

    pub fn encode(self, dst: &mut BytesMut) -> Result<()> {
        match self {
            PostgresFrame::Request(message) => message.encode(dst),
            PostgresFrame::Response(messages) => {
                for message in messages {
                    message.encode(dst)?;
                }
                Ok(())
            }
        }
    }

    pub fn as_codec_state(&self) -> PostgresCodecState {
        match self {
            PostgresFrame::Request(message) => PostgresCodecState::request(matches!(
                message,
                FrontendMessage::Startup { .. } | FrontendMessage::CancelRequest { .. }
            )),
            // A frame carries no record of having been a partial chunk, so a message REBUILT from
            // one via `Message::from_frame` claims to be a whole response. Transforms that branch
            // on `partial` must mutate a partial in place, which preserves its codec state, rather
            // than reconstruct it.
            PostgresFrame::Response(_) => PostgresCodecState::response(),
        }
    }
}

/// Splits a tagged message into its tag and body, validating the length header.
fn split_tagged_message(mut bytes: Bytes) -> Result<(u8, Bytes)> {
    if bytes.len() < 5 {
        return Err(anyhow!(
            "Postgres message too short to hold tag and length: {} bytes",
            bytes.len()
        ));
    }
    let tag = bytes.get_u8();
    let length = bytes.get_i32();
    if length as usize != bytes.len() + 4 {
        return Err(anyhow!(
            "Postgres message length header {length} does not match actual body length {}",
            bytes.len()
        ));
    }
    Ok((tag, bytes))
}

fn parse_startup_family(mut bytes: Bytes) -> Result<FrontendMessage> {
    if bytes.len() < 8 {
        return Err(anyhow!("Postgres startup packet too short"));
    }
    let length = bytes.get_i32();
    if length as usize != bytes.len() + 4 {
        return Err(anyhow!(
            "Postgres startup packet length header {length} does not match actual length {}",
            bytes.len() + 4
        ));
    }
    let code = bytes.get_i32();
    match code {
        CANCEL_REQUEST_CODE => {
            if bytes.remaining() < 4 {
                return Err(anyhow!("CancelRequest message truncated"));
            }
            Ok(FrontendMessage::CancelRequest {
                process_id: bytes.get_i32(),
                secret_key: bytes,
            })
        }
        // SSLRequest/GSSENCRequest are answered inside the connection prologue and never reach
        // frame parsing. If a packet carrying one of these codes (but not the exact 8-byte form)
        // does reach here it is malformed; reject it rather than rewrite it into a lossy Raw frame
        // that would not round-trip byte-identically.
        SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => Err(anyhow!(
            "Unexpected SSL/GSS request code in a framed startup message (handled by the prologue)"
        )),
        protocol_version => {
            let mut parameters = vec![];
            loop {
                let name = get_cstring(&mut bytes)?;
                if name.is_empty() {
                    break;
                }
                let value = get_cstring(&mut bytes)?;
                parameters.push((name, value));
            }
            Ok(FrontendMessage::Startup {
                protocol_version,
                parameters,
            })
        }
    }
}

fn get_cstring(bytes: &mut Bytes) -> Result<String> {
    match bytes.iter().position(|b| *b == 0) {
        Some(null_at) => {
            let value = bytes.split_to(null_at);
            bytes.advance(1);
            Ok(String::from_utf8(value.to_vec())?)
        }
        None => Err(anyhow!("Unterminated string in postgres message")),
    }
}

fn put_cstring(dst: &mut BytesMut, value: &str) {
    dst.extend_from_slice(value.as_bytes());
    dst.put_u8(0);
}

/// Writes one tagged message: tag byte, then a length prefixed body produced by `body`.
fn write_tagged_message(
    dst: &mut BytesMut,
    tag: u8,
    body: impl FnOnce(&mut BytesMut),
) -> Result<()> {
    dst.put_u8(tag);
    let length_at = dst.len();
    dst.put_i32(0);
    body(dst);
    let length = (dst.len() - length_at) as i32;
    dst[length_at..length_at + 4].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

impl FrontendMessage {
    /// Parses a tagged frontend message body.
    /// A failed typed parse degrades to `Raw`, which round-trips byte identically.
    pub fn parse(tag: u8, body: Bytes) -> FrontendMessage {
        Self::parse_typed(tag, body.clone()).unwrap_or(FrontendMessage::Raw { tag, body })
    }

    fn parse_typed(tag: u8, mut body: Bytes) -> Result<FrontendMessage> {
        Ok(match tag {
            b'Q' => FrontendMessage::Query {
                query: get_cstring(&mut body)?,
            },
            b'P' => {
                let statement_name = get_cstring(&mut body)?;
                let query = get_cstring(&mut body)?;
                let count = checked_i16_count(&mut body, 4)?;
                let mut parameter_data_types = Vec::with_capacity(count);
                for _ in 0..count {
                    parameter_data_types.push(body.get_i32());
                }
                FrontendMessage::Parse {
                    statement_name,
                    query,
                    parameter_data_types,
                }
            }
            b'B' => {
                let portal_name = get_cstring(&mut body)?;
                let statement_name = get_cstring(&mut body)?;
                let format_count = checked_i16_count(&mut body, 2)?;
                let mut parameter_format_codes = Vec::with_capacity(format_count);
                for _ in 0..format_count {
                    parameter_format_codes.push(body.get_i16());
                }
                let value_count = checked_i16_count(&mut body, 4)?;
                let mut parameter_values = Vec::with_capacity(value_count);
                for _ in 0..value_count {
                    if body.remaining() < 4 {
                        return Err(anyhow!("Bind message truncated"));
                    }
                    let length = body.get_i32();
                    parameter_values.push(if length < 0 {
                        None
                    } else {
                        if body.remaining() < length as usize {
                            return Err(anyhow!("Bind message truncated"));
                        }
                        Some(body.split_to(length as usize))
                    });
                }
                let result_count = checked_i16_count(&mut body, 2)?;
                let mut result_format_codes = Vec::with_capacity(result_count);
                for _ in 0..result_count {
                    result_format_codes.push(body.get_i16());
                }
                FrontendMessage::Bind {
                    portal_name,
                    statement_name,
                    parameter_format_codes,
                    parameter_values,
                    result_format_codes,
                }
            }
            b'D' => {
                if body.remaining() < 1 {
                    return Err(anyhow!("Describe message truncated"));
                }
                FrontendMessage::Describe {
                    kind: body.get_u8(),
                    name: get_cstring(&mut body)?,
                }
            }
            b'E' => {
                let portal_name = get_cstring(&mut body)?;
                if body.remaining() < 4 {
                    return Err(anyhow!("Execute message truncated"));
                }
                FrontendMessage::Execute {
                    portal_name,
                    max_rows: body.get_i32(),
                }
            }
            b'S' => FrontendMessage::Sync,
            b'H' => FrontendMessage::Flush,
            b'C' => {
                if body.remaining() < 1 {
                    return Err(anyhow!("Close message truncated"));
                }
                FrontendMessage::Close {
                    kind: body.get_u8(),
                    name: get_cstring(&mut body)?,
                }
            }
            b'd' => FrontendMessage::CopyData(body),
            b'c' => FrontendMessage::CopyDone,
            b'f' => FrontendMessage::CopyFail {
                message: get_cstring(&mut body)?,
            },
            b'p' => FrontendMessage::AuthenticationData(body),
            b'X' => FrontendMessage::Terminate,
            _ => return Err(anyhow!("Unmodeled frontend message tag {:?}", tag as char)),
        })
    }

    pub fn tag(&self) -> Option<u8> {
        Some(match self {
            FrontendMessage::Startup { .. } | FrontendMessage::CancelRequest { .. } => return None,
            FrontendMessage::Query { .. } => b'Q',
            FrontendMessage::Parse { .. } => b'P',
            FrontendMessage::Bind { .. } => b'B',
            FrontendMessage::Describe { .. } => b'D',
            FrontendMessage::Execute { .. } => b'E',
            FrontendMessage::Sync => b'S',
            FrontendMessage::Flush => b'H',
            FrontendMessage::Close { .. } => b'C',
            FrontendMessage::CopyData(_) => b'd',
            FrontendMessage::CopyDone => b'c',
            FrontendMessage::CopyFail { .. } => b'f',
            FrontendMessage::AuthenticationData(_) => b'p',
            FrontendMessage::Terminate => b'X',
            FrontendMessage::Raw { tag, .. } => *tag,
        })
    }

    pub fn encode(self, dst: &mut BytesMut) -> Result<()> {
        match self {
            FrontendMessage::Startup {
                protocol_version,
                parameters,
            } => {
                let length_at = dst.len();
                dst.put_i32(0);
                dst.put_i32(protocol_version);
                for (name, value) in &parameters {
                    put_cstring(dst, name);
                    put_cstring(dst, value);
                }
                dst.put_u8(0);
                let length = (dst.len() - length_at) as i32;
                dst[length_at..length_at + 4].copy_from_slice(&length.to_be_bytes());
                Ok(())
            }
            FrontendMessage::CancelRequest {
                process_id,
                secret_key,
            } => {
                dst.put_i32(12 + secret_key.len() as i32);
                dst.put_i32(CANCEL_REQUEST_CODE);
                dst.put_i32(process_id);
                dst.extend_from_slice(&secret_key);
                Ok(())
            }
            FrontendMessage::Query { query } => {
                write_tagged_message(dst, b'Q', |dst| put_cstring(dst, &query))
            }
            FrontendMessage::Parse {
                statement_name,
                query,
                parameter_data_types,
            } => write_tagged_message(dst, b'P', |dst| {
                put_cstring(dst, &statement_name);
                put_cstring(dst, &query);
                dst.put_i16(parameter_data_types.len() as i16);
                for data_type in &parameter_data_types {
                    dst.put_i32(*data_type);
                }
            }),
            FrontendMessage::Bind {
                portal_name,
                statement_name,
                parameter_format_codes,
                parameter_values,
                result_format_codes,
            } => write_tagged_message(dst, b'B', |dst| {
                put_cstring(dst, &portal_name);
                put_cstring(dst, &statement_name);
                dst.put_i16(parameter_format_codes.len() as i16);
                for code in &parameter_format_codes {
                    dst.put_i16(*code);
                }
                dst.put_i16(parameter_values.len() as i16);
                for value in &parameter_values {
                    match value {
                        Some(value) => {
                            dst.put_i32(value.len() as i32);
                            dst.extend_from_slice(value);
                        }
                        None => dst.put_i32(-1),
                    }
                }
                dst.put_i16(result_format_codes.len() as i16);
                for code in &result_format_codes {
                    dst.put_i16(*code);
                }
            }),
            FrontendMessage::Describe { kind, name } => write_tagged_message(dst, b'D', |dst| {
                dst.put_u8(kind);
                put_cstring(dst, &name);
            }),
            FrontendMessage::Execute {
                portal_name,
                max_rows,
            } => write_tagged_message(dst, b'E', |dst| {
                put_cstring(dst, &portal_name);
                dst.put_i32(max_rows);
            }),
            FrontendMessage::Sync => write_tagged_message(dst, b'S', |_| {}),
            FrontendMessage::Flush => write_tagged_message(dst, b'H', |_| {}),
            FrontendMessage::Close { kind, name } => write_tagged_message(dst, b'C', |dst| {
                dst.put_u8(kind);
                put_cstring(dst, &name);
            }),
            FrontendMessage::CopyData(data) => {
                write_tagged_message(dst, b'd', |dst| dst.extend_from_slice(&data))
            }
            FrontendMessage::CopyDone => write_tagged_message(dst, b'c', |_| {}),
            FrontendMessage::CopyFail { message } => {
                write_tagged_message(dst, b'f', |dst| put_cstring(dst, &message))
            }
            FrontendMessage::AuthenticationData(data) => {
                write_tagged_message(dst, b'p', |dst| dst.extend_from_slice(&data))
            }
            FrontendMessage::Terminate => write_tagged_message(dst, b'X', |_| {}),
            FrontendMessage::Raw { tag, body } => {
                write_tagged_message(dst, tag, |dst| dst.extend_from_slice(&body))
            }
        }
    }
}

/// Reads an i16 element count, validating against the space its elements need.
fn checked_i16_count(body: &mut Bytes, min_element_size: usize) -> Result<usize> {
    if body.remaining() < 2 {
        return Err(anyhow!("Postgres message truncated before element count"));
    }
    let count = body.get_i16();
    if count < 0 || body.remaining() < count as usize * min_element_size {
        return Err(anyhow!(
            "Postgres message element count {count} exceeds message size"
        ));
    }
    Ok(count as usize)
}

impl BackendMessage {
    /// Parses a tagged backend message body.
    /// A failed typed parse degrades to `Raw`, which round-trips byte identically.
    pub fn parse(tag: u8, body: Bytes) -> BackendMessage {
        Self::parse_typed(tag, body.clone()).unwrap_or(BackendMessage::Raw { tag, body })
    }

    fn parse_typed(tag: u8, mut body: Bytes) -> Result<BackendMessage> {
        Ok(match tag {
            b'R' => {
                if body.remaining() < 4 {
                    return Err(anyhow!("Authentication message truncated"));
                }
                BackendMessage::Authentication(match body.get_i32() {
                    0 => AuthenticationMessage::Ok,
                    3 => AuthenticationMessage::CleartextPassword,
                    5 => {
                        if body.remaining() < 4 {
                            return Err(anyhow!("MD5Password message truncated"));
                        }
                        let mut salt = [0u8; 4];
                        body.copy_to_slice(&mut salt);
                        AuthenticationMessage::Md5Password { salt }
                    }
                    10 => {
                        let mut mechanisms = vec![];
                        loop {
                            let mechanism = get_cstring(&mut body)?;
                            if mechanism.is_empty() {
                                break;
                            }
                            mechanisms.push(mechanism);
                        }
                        AuthenticationMessage::Sasl { mechanisms }
                    }
                    11 => AuthenticationMessage::SaslContinue { data: body },
                    12 => AuthenticationMessage::SaslFinal { data: body },
                    code => AuthenticationMessage::Other { code, data: body },
                })
            }
            b'K' => {
                if body.remaining() < 4 {
                    return Err(anyhow!("BackendKeyData message truncated"));
                }
                BackendMessage::BackendKeyData {
                    process_id: body.get_i32(),
                    secret_key: body,
                }
            }
            b'S' => BackendMessage::ParameterStatus {
                name: get_cstring(&mut body)?,
                value: get_cstring(&mut body)?,
            },
            b'Z' => {
                if body.remaining() < 1 {
                    return Err(anyhow!("ReadyForQuery message truncated"));
                }
                BackendMessage::ReadyForQuery {
                    status: body.get_u8(),
                }
            }
            b'T' => {
                let count = checked_i16_count(&mut body, 18)?;
                let mut fields = Vec::with_capacity(count);
                for _ in 0..count {
                    let name = get_cstring(&mut body)?;
                    if body.remaining() < 18 {
                        return Err(anyhow!("RowDescription message truncated"));
                    }
                    fields.push(FieldDescription {
                        name,
                        table_oid: body.get_i32(),
                        column_attribute_number: body.get_i16(),
                        data_type_oid: body.get_i32(),
                        data_type_size: body.get_i16(),
                        type_modifier: body.get_i32(),
                        format_code: body.get_i16(),
                    });
                }
                BackendMessage::RowDescription { fields }
            }
            b'D' => {
                let count = checked_i16_count(&mut body, 4)?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    if body.remaining() < 4 {
                        return Err(anyhow!("DataRow message truncated"));
                    }
                    let length = body.get_i32();
                    values.push(if length < 0 {
                        None
                    } else {
                        if body.remaining() < length as usize {
                            return Err(anyhow!("DataRow message truncated"));
                        }
                        Some(body.split_to(length as usize))
                    });
                }
                BackendMessage::DataRow { values }
            }
            b'C' => BackendMessage::CommandComplete {
                tag: get_cstring(&mut body)?,
            },
            b'I' => BackendMessage::EmptyQueryResponse,
            b'E' => BackendMessage::ErrorResponse {
                fields: parse_error_fields(&mut body)?,
            },
            b'N' => BackendMessage::NoticeResponse {
                fields: parse_error_fields(&mut body)?,
            },
            b'1' => BackendMessage::ParseComplete,
            b'2' => BackendMessage::BindComplete,
            b'3' => BackendMessage::CloseComplete,
            b'n' => BackendMessage::NoData,
            b't' => {
                let count = checked_i16_count(&mut body, 4)?;
                let mut parameter_data_types = Vec::with_capacity(count);
                for _ in 0..count {
                    parameter_data_types.push(body.get_i32());
                }
                BackendMessage::ParameterDescription {
                    parameter_data_types,
                }
            }
            b's' => BackendMessage::PortalSuspended,
            b'G' => parse_copy_response(&mut body, CopyResponseKind::In)?,
            b'H' => parse_copy_response(&mut body, CopyResponseKind::Out)?,
            b'W' => parse_copy_response(&mut body, CopyResponseKind::Both)?,
            b'd' => BackendMessage::CopyData(body),
            b'c' => BackendMessage::CopyDone,
            b'A' => {
                if body.remaining() < 4 {
                    return Err(anyhow!("NotificationResponse message truncated"));
                }
                BackendMessage::NotificationResponse {
                    process_id: body.get_i32(),
                    channel: get_cstring(&mut body)?,
                    payload: get_cstring(&mut body)?,
                }
            }
            b'v' => {
                if body.remaining() < 8 {
                    return Err(anyhow!("NegotiateProtocolVersion message truncated"));
                }
                let newest_minor_version = body.get_i32();
                let count = body.get_i32();
                if count < 0 || count as usize > body.remaining() {
                    return Err(anyhow!("NegotiateProtocolVersion option count invalid"));
                }
                let mut unsupported_options = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    unsupported_options.push(get_cstring(&mut body)?);
                }
                BackendMessage::NegotiateProtocolVersion {
                    newest_minor_version,
                    unsupported_options,
                }
            }
            _ => return Err(anyhow!("Unmodeled backend message tag {:?}", tag as char)),
        })
    }

    pub fn tag(&self) -> u8 {
        match self {
            BackendMessage::Authentication(_) => b'R',
            BackendMessage::BackendKeyData { .. } => b'K',
            BackendMessage::ParameterStatus { .. } => b'S',
            BackendMessage::ReadyForQuery { .. } => b'Z',
            BackendMessage::RowDescription { .. } => b'T',
            BackendMessage::DataRow { .. } => b'D',
            BackendMessage::CommandComplete { .. } => b'C',
            BackendMessage::EmptyQueryResponse => b'I',
            BackendMessage::ErrorResponse { .. } => b'E',
            BackendMessage::NoticeResponse { .. } => b'N',
            BackendMessage::ParseComplete => b'1',
            BackendMessage::BindComplete => b'2',
            BackendMessage::CloseComplete => b'3',
            BackendMessage::NoData => b'n',
            BackendMessage::ParameterDescription { .. } => b't',
            BackendMessage::PortalSuspended => b's',
            BackendMessage::CopyInResponse { .. } => b'G',
            BackendMessage::CopyOutResponse { .. } => b'H',
            BackendMessage::CopyBothResponse { .. } => b'W',
            BackendMessage::CopyData(_) => b'd',
            BackendMessage::CopyDone => b'c',
            BackendMessage::NotificationResponse { .. } => b'A',
            BackendMessage::NegotiateProtocolVersion { .. } => b'v',
            BackendMessage::Raw { tag, .. } => *tag,
        }
    }

    pub fn encode(self, dst: &mut BytesMut) -> Result<()> {
        match self {
            BackendMessage::Authentication(message) => {
                write_tagged_message(dst, b'R', |dst| match message {
                    AuthenticationMessage::Ok => dst.put_i32(0),
                    AuthenticationMessage::CleartextPassword => dst.put_i32(3),
                    AuthenticationMessage::Md5Password { salt } => {
                        dst.put_i32(5);
                        dst.extend_from_slice(&salt);
                    }
                    AuthenticationMessage::Sasl { mechanisms } => {
                        dst.put_i32(10);
                        for mechanism in &mechanisms {
                            put_cstring(dst, mechanism);
                        }
                        dst.put_u8(0);
                    }
                    AuthenticationMessage::SaslContinue { data } => {
                        dst.put_i32(11);
                        dst.extend_from_slice(&data);
                    }
                    AuthenticationMessage::SaslFinal { data } => {
                        dst.put_i32(12);
                        dst.extend_from_slice(&data);
                    }
                    AuthenticationMessage::Other { code, data } => {
                        dst.put_i32(code);
                        dst.extend_from_slice(&data);
                    }
                })
            }
            BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            } => write_tagged_message(dst, b'K', |dst| {
                dst.put_i32(process_id);
                dst.extend_from_slice(&secret_key);
            }),
            BackendMessage::ParameterStatus { name, value } => {
                write_tagged_message(dst, b'S', |dst| {
                    put_cstring(dst, &name);
                    put_cstring(dst, &value);
                })
            }
            BackendMessage::ReadyForQuery { status } => {
                write_tagged_message(dst, b'Z', |dst| dst.put_u8(status))
            }
            BackendMessage::RowDescription { fields } => write_tagged_message(dst, b'T', |dst| {
                dst.put_i16(fields.len() as i16);
                for field in &fields {
                    put_cstring(dst, &field.name);
                    dst.put_i32(field.table_oid);
                    dst.put_i16(field.column_attribute_number);
                    dst.put_i32(field.data_type_oid);
                    dst.put_i16(field.data_type_size);
                    dst.put_i32(field.type_modifier);
                    dst.put_i16(field.format_code);
                }
            }),
            BackendMessage::DataRow { values } => write_tagged_message(dst, b'D', |dst| {
                dst.put_i16(values.len() as i16);
                for value in &values {
                    match value {
                        Some(value) => {
                            dst.put_i32(value.len() as i32);
                            dst.extend_from_slice(value);
                        }
                        None => dst.put_i32(-1),
                    }
                }
            }),
            BackendMessage::CommandComplete { tag } => {
                write_tagged_message(dst, b'C', |dst| put_cstring(dst, &tag))
            }
            BackendMessage::EmptyQueryResponse => write_tagged_message(dst, b'I', |_| {}),
            BackendMessage::ErrorResponse { fields } => {
                write_tagged_message(dst, b'E', |dst| encode_error_fields(dst, &fields))
            }
            BackendMessage::NoticeResponse { fields } => {
                write_tagged_message(dst, b'N', |dst| encode_error_fields(dst, &fields))
            }
            BackendMessage::ParseComplete => write_tagged_message(dst, b'1', |_| {}),
            BackendMessage::BindComplete => write_tagged_message(dst, b'2', |_| {}),
            BackendMessage::CloseComplete => write_tagged_message(dst, b'3', |_| {}),
            BackendMessage::NoData => write_tagged_message(dst, b'n', |_| {}),
            BackendMessage::ParameterDescription {
                parameter_data_types,
            } => write_tagged_message(dst, b't', |dst| {
                dst.put_i16(parameter_data_types.len() as i16);
                for data_type in &parameter_data_types {
                    dst.put_i32(*data_type);
                }
            }),
            BackendMessage::PortalSuspended => write_tagged_message(dst, b's', |_| {}),
            BackendMessage::CopyInResponse {
                overall_format,
                column_formats,
            } => encode_copy_response(dst, b'G', overall_format, &column_formats),
            BackendMessage::CopyOutResponse {
                overall_format,
                column_formats,
            } => encode_copy_response(dst, b'H', overall_format, &column_formats),
            BackendMessage::CopyBothResponse {
                overall_format,
                column_formats,
            } => encode_copy_response(dst, b'W', overall_format, &column_formats),
            BackendMessage::CopyData(data) => {
                write_tagged_message(dst, b'd', |dst| dst.extend_from_slice(&data))
            }
            BackendMessage::CopyDone => write_tagged_message(dst, b'c', |_| {}),
            BackendMessage::NotificationResponse {
                process_id,
                channel,
                payload,
            } => write_tagged_message(dst, b'A', |dst| {
                dst.put_i32(process_id);
                put_cstring(dst, &channel);
                put_cstring(dst, &payload);
            }),
            BackendMessage::NegotiateProtocolVersion {
                newest_minor_version,
                unsupported_options,
            } => write_tagged_message(dst, b'v', |dst| {
                dst.put_i32(newest_minor_version);
                dst.put_i32(unsupported_options.len() as i32);
                for option in &unsupported_options {
                    put_cstring(dst, option);
                }
            }),
            BackendMessage::Raw { tag, body } => {
                write_tagged_message(dst, tag, |dst| dst.extend_from_slice(&body))
            }
        }
    }
}

enum CopyResponseKind {
    In,
    Out,
    Both,
}

fn parse_copy_response(body: &mut Bytes, kind: CopyResponseKind) -> Result<BackendMessage> {
    if body.remaining() < 1 {
        return Err(anyhow!("Copy response message truncated"));
    }
    let overall_format = body.get_i8();
    let count = checked_i16_count(body, 2)?;
    let mut column_formats = Vec::with_capacity(count);
    for _ in 0..count {
        column_formats.push(body.get_i16());
    }
    Ok(match kind {
        CopyResponseKind::In => BackendMessage::CopyInResponse {
            overall_format,
            column_formats,
        },
        CopyResponseKind::Out => BackendMessage::CopyOutResponse {
            overall_format,
            column_formats,
        },
        CopyResponseKind::Both => BackendMessage::CopyBothResponse {
            overall_format,
            column_formats,
        },
    })
}

fn encode_copy_response(
    dst: &mut BytesMut,
    tag: u8,
    overall_format: i8,
    column_formats: &[i16],
) -> Result<()> {
    write_tagged_message(dst, tag, |dst| {
        dst.put_i8(overall_format);
        dst.put_i16(column_formats.len() as i16);
        for format in column_formats {
            dst.put_i16(*format);
        }
    })
}

fn parse_error_fields(body: &mut Bytes) -> Result<Vec<(u8, String)>> {
    let mut fields = vec![];
    loop {
        if body.remaining() < 1 {
            return Err(anyhow!("Error/notice message truncated"));
        }
        let field_type = body.get_u8();
        if field_type == 0 {
            break;
        }
        fields.push((field_type, get_cstring(body)?));
    }
    Ok(fields)
}

fn encode_error_fields(dst: &mut BytesMut, fields: &[(u8, String)]) {
    for (field_type, value) in fields {
        dst.put_u8(*field_type);
        put_cstring(dst, value);
    }
    dst.put_u8(0);
}

impl BackendMessage {
    /// The human readable message of an error response, if this is one.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            BackendMessage::ErrorResponse { fields } => fields
                .iter()
                .find(|(field_type, _)| *field_type == b'M')
                .map(|(_, value)| value.as_str()),
            _ => None,
        }
    }

    /// The SQLSTATE code (the `C` field) of an error response, if this is one.
    pub fn error_code(&self) -> Option<&str> {
        match self {
            BackendMessage::ErrorResponse { fields } => fields
                .iter()
                .find(|(field_type, _)| *field_type == b'C')
                .map(|(_, value)| value.as_str()),
            _ => None,
        }
    }
}

impl Display for PostgresFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            PostgresFrame::Request(message) => match message {
                FrontendMessage::Query { query } => write!(f, "Query {query:?}"),
                FrontendMessage::Parse {
                    statement_name,
                    query,
                    ..
                } => write!(f, "Parse {statement_name:?} {query:?}"),
                FrontendMessage::Startup { parameters, .. } => {
                    write!(f, "Startup {parameters:?}")
                }
                other => write!(f, "{other:?}"),
            },
            PostgresFrame::Response(messages) => {
                write!(f, "Response[")?;
                let mut names: Vec<(&'static str, usize)> = vec![];
                for message in messages {
                    let name = match message {
                        BackendMessage::Authentication(_) => "Authentication",
                        BackendMessage::BackendKeyData { .. } => "BackendKeyData",
                        BackendMessage::ParameterStatus { .. } => "ParameterStatus",
                        BackendMessage::ReadyForQuery { .. } => "ReadyForQuery",
                        BackendMessage::RowDescription { .. } => "RowDescription",
                        BackendMessage::DataRow { .. } => "DataRow",
                        BackendMessage::CommandComplete { .. } => "CommandComplete",
                        BackendMessage::EmptyQueryResponse => "EmptyQueryResponse",
                        BackendMessage::ErrorResponse { .. } => "ErrorResponse",
                        BackendMessage::NoticeResponse { .. } => "NoticeResponse",
                        BackendMessage::ParseComplete => "ParseComplete",
                        BackendMessage::BindComplete => "BindComplete",
                        BackendMessage::CloseComplete => "CloseComplete",
                        BackendMessage::NoData => "NoData",
                        BackendMessage::ParameterDescription { .. } => "ParameterDescription",
                        BackendMessage::PortalSuspended => "PortalSuspended",
                        BackendMessage::CopyInResponse { .. } => "CopyInResponse",
                        BackendMessage::CopyOutResponse { .. } => "CopyOutResponse",
                        BackendMessage::CopyBothResponse { .. } => "CopyBothResponse",
                        BackendMessage::CopyData(_) => "CopyData",
                        BackendMessage::CopyDone => "CopyDone",
                        BackendMessage::NotificationResponse { .. } => "NotificationResponse",
                        BackendMessage::NegotiateProtocolVersion { .. } => {
                            "NegotiateProtocolVersion"
                        }
                        BackendMessage::Raw { .. } => "Raw",
                    };
                    match names.last_mut() {
                        Some((last, count)) if *last == name => *count += 1,
                        _ => names.push((name, 1)),
                    }
                }
                for (i, (name, count)) in names.iter().enumerate() {
                    if i != 0 {
                        write!(f, ", ")?;
                    }
                    if *count == 1 {
                        write!(f, "{name}")?;
                    } else {
                        write!(f, "{name} x{count}")?;
                    }
                }
                write!(f, "]")
            }
        }
    }
}

/// The counter name QueryCounter reports for a request: the leading SQL keyword
/// for queries, the message name for other frontend messages.
pub fn query_name(frame: &PostgresFrame) -> Option<String> {
    match frame {
        PostgresFrame::Request(
            FrontendMessage::Query { query } | FrontendMessage::Parse { query, .. },
        ) => query
            .split_whitespace()
            .next()
            .map(|word| word.to_ascii_uppercase()),
        PostgresFrame::Request(message) => Some(
            match message {
                FrontendMessage::Startup { .. } => "Startup",
                FrontendMessage::CancelRequest { .. } => "CancelRequest",
                FrontendMessage::Bind { .. } => "Bind",
                FrontendMessage::Describe { .. } => "Describe",
                FrontendMessage::Execute { .. } => "Execute",
                FrontendMessage::Sync => "Sync",
                FrontendMessage::Flush => "Flush",
                FrontendMessage::Close { .. } => "Close",
                FrontendMessage::CopyData(_) => "CopyData",
                FrontendMessage::CopyDone => "CopyDone",
                FrontendMessage::CopyFail { .. } => "CopyFail",
                FrontendMessage::AuthenticationData(_) => "AuthenticationData",
                FrontendMessage::Terminate => "Terminate",
                FrontendMessage::Query { .. }
                | FrontendMessage::Parse { .. }
                | FrontendMessage::Raw { .. } => return None,
            }
            .to_owned(),
        ),
        PostgresFrame::Response(_) => None,
    }
}

/// Classifies a request for QueryCounter and QueryTypeFilter.
/// The result of statically analysing a SQL string with the real postgres grammar.
/// Transaction-control effect of a statement, from pg_query's `TransactionStmt.kind`. Used by
/// PostgresReadCache to know when to apply or discard its deferred invalidation across BOTH the simple
/// and extended protocols (a bare `starts_with("rollback")` wrongly caught `ROLLBACK TO SAVEPOINT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnControl {
    /// BEGIN / START TRANSACTION — opens an explicit transaction.
    Begin,
    /// COMMIT / END / PREPARE TRANSACTION — ends it; apply the deferred invalidation. `chain` (AND
    /// CHAIN) immediately opens a new transaction, so the session stays in one.
    Commit { chain: bool },
    /// ROLLBACK / ABORT — ends it; discard the deferred invalidation. `chain` opens a new one.
    Rollback { chain: bool },
    /// COMMIT PREPARED — commits a two-phase transaction that may have been PREPAREd on a DIFFERENT
    /// connection, so its writes are unknown here; a cache must evict everything (review Y7). Runs
    /// standalone (never inside a transaction block).
    CommitPrepared,
    /// SAVEPOINT / RELEASE / ROLLBACK TO / ROLLBACK PREPARED — does NOT end the current transaction (or,
    /// for ROLLBACK PREPARED, aborts a two-phase txn that committed nothing); keep the deferred set.
    Nested,
}

/// Drives both query classification (QueryCounter/QueryTypeFilter) and read/write-split routing.
#[derive(Debug, Clone, PartialEq)]
pub struct SqlAnalysis {
    pub query_type: crate::message::QueryType,
    /// True iff every statement is a pure read: safe to route to a read replica.
    /// A statement is NOT replica-safe if it writes (incl. a data-modifying CTE), is DDL,
    /// takes row locks (FOR UPDATE/SHARE), does SELECT INTO, calls a known writing function
    /// (nextval/setval), or is anything the analysis could not prove read-only.
    pub replica_safe: bool,
    /// The statement changes session state that later statements may depend on
    /// (SET, named PREPARE, LISTEN, DECLARE CURSOR, temp table): once seen, the whole
    /// session must pin to the primary so that state is visible to subsequent requests.
    pub pins_session: bool,
    /// Relations a pure read reads (pg_query `select_tables`); empty for a non-read. Names are as
    /// pg_query returns them (schema-qualified iff the SQL qualified them). Used by PostgresReadCache
    /// to record what a cached entry depends on; the cluster router ignores it.
    pub reads: Vec<String>,
    /// Relations a write or DDL targets (`dml_tables` ∪ `ddl_tables`). Used to evict cached reads of
    /// them on the write path.
    pub writes: Vec<String>,
    /// A statement that has an effect but whose target relations are UNKNOWN — a writing function, a
    /// `DO` block, `CALL`, `COPY ... FROM`, or an unparseable statement — so a cache must evict
    /// everything rather than risk serving stale data.
    pub opaque_write: bool,
    /// Bare, lowercased names of every function the statement CALLS (pg_query `functions`). A read that
    /// calls a function whose body the proxy cannot see (any user function) might write; PostgresReadCache
    /// uses this to refuse to cache such a read and to invalidate for it. Empty for a parse failure.
    pub functions: Vec<String>,
    /// Present iff the statement is transaction control (BEGIN/COMMIT/…). Lets the cache track
    /// transaction boundaries precisely and across the extended protocol. `None` for everything else.
    pub txn: Option<TxnControl>,
}

/// True if a RangeVar names a temporary relation (relpersistence 't').
fn range_var_is_temp(rel: Option<&pg_query::protobuf::RangeVar>) -> bool {
    rel.map(|r| r.relpersistence == "t").unwrap_or(false)
}

/// True if an IntoClause targets a temporary relation (SELECT INTO TEMP / CREATE TEMP TABLE AS).
fn into_clause_is_temp(into: Option<&pg_query::protobuf::IntoClause>) -> bool {
    range_var_is_temp(into.and_then(|i| i.rel.as_ref()))
}

/// Functions that write, take a lock, or change session state despite appearing inside an
/// otherwise read-only statement, so a statement calling one must go to the primary. Some of these
/// error on a read-only replica (`nextval`), but the dangerous ones SUCCEED on a replica with the
/// wrong effect: an advisory lock taken on a replica does not exclude anything on the primary, and
/// `set_config` mutates the replica session.
///
/// This list is best-effort and cannot be complete — any volatile or user-defined function may
/// write, and a `SELECT` that calls one is not detected here. It covers the common built-ins whose
/// silent misbehaviour on a replica is worst.
pub(crate) fn is_writing_function(name: &str) -> bool {
    let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase();
    // Advisory locks in all forms (pg_advisory_lock, pg_try_advisory_xact_lock_shared, …): taking
    // one on a replica silently breaks the mutual exclusion the caller intended.
    if bare.starts_with("pg_advisory_") || bare.starts_with("pg_try_advisory_") {
        return true;
    }
    matches!(
        bare.as_str(),
        // Sequence access and mutation.
        "nextval" | "setval" | "currval" | "lastval"
        // set_config() is the function form of SET: it mutates session state.
        | "set_config"
        // Transaction id assignment.
        | "txid_current" | "pg_current_xact_id"
        // Replication / recovery side effects.
        | "pg_logical_emit_message"
        | "pg_create_restore_point"
        | "pg_replication_origin_session_setup"
        | "pg_replication_origin_xact_setup"
    )
}

/// True for `set_config`, the function form of SET — it mutates a session GUC, so like SET it must pin
/// the session to the primary (see analyze_sql). Kept separate from is_writing_function because that
/// set also includes functions that route to the primary but need no session pin.
fn is_set_config(name: &str) -> bool {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .eq_ignore_ascii_case("set_config")
}

/// Analyses a SQL string using the postgres grammar (libpg_query via pg_query).
/// Falls back to a keyword heuristic when the parser cannot parse the string.
pub fn analyze_sql(sql: &str) -> SqlAnalysis {
    use crate::message::QueryType;
    use pg_query::NodeEnum;

    let parsed = match pg_query::parse(sql) {
        Ok(parsed) => parsed,
        // An empty statement (e.g. just a comment) is a harmless read; anything else that
        // fails to parse is routed conservatively via the keyword fallback.
        Err(_) => {
            return SqlAnalysis {
                query_type: query_type_by_keyword(sql),
                replica_safe: false,
                pins_session: false,
                reads: Vec::new(),
                writes: Vec::new(),
                // Unparseable and not provably a read: a cache must assume it could have written.
                opaque_write: true,
                functions: Vec::new(),
                txn: None,
            };
        }
    };

    // These helpers walk the ENTIRE parse tree, so a DML statement hidden in a CTE
    // (WITH x AS (INSERT ...) SELECT ...) is caught here as a write.
    let writes_tables = !parsed.dml_tables().is_empty();
    let ddl_tables = !parsed.ddl_tables().is_empty();
    let functions = parsed.functions();
    let writing_function = functions.iter().any(|f| is_writing_function(f));
    // set_config() is the function form of SET: it mutates a session GUC (search_path, timezone, …)
    // that EVERY subsequent query depends on. Like SET (VariableSetStmt below) it MUST pin the session
    // to the primary, or a following replica-safe read hits a replica that never saw the change —
    // silent wrong results (e.g. a multi-tenant search_path resolving to the wrong schema, a
    // cross-tenant read). The sibling writing-functions do not share this: they either route to the
    // primary themselves (currval/lastval/advisory locks) or change no state a plain read observes.
    let sets_session_state = functions.iter().any(|f| is_set_config(f));

    // Row-level lock clauses (FOR UPDATE/SHARE/NO KEY UPDATE/KEY SHARE) can sit in a subquery or
    // CTE where the top-level SelectStmt.locking_clause check below does not see them, e.g.
    // `WITH x AS (SELECT * FROM t FOR UPDATE) SELECT * FROM x`. Such a statement takes locks and
    // errors on a read-only replica, so it must not be replica-safe. pg_query exposes no locking
    // helper, so detect a LockingClause node anywhere in the tree via the debug representation of
    // the parse tree (which reflects the AST, not the SQL text, so string literals cannot trip it).
    // `test_analyze_row_locks_anywhere` pins this so a pg_query format change fails loudly rather
    // than silently routing a lock to a replica.
    let has_row_lock = format!("{:?}", parsed.protobuf).contains("LockingClause");

    let mut replica_safe = !writes_tables && !ddl_tables && !writing_function && !has_row_lock;
    let mut pins_session = sets_session_state;
    let mut saw_read = false;
    let mut saw_write = writes_tables || has_row_lock;
    let mut saw_ddl = ddl_tables;
    // For PostgresReadCache invalidation: a data write whose target tables cannot be enumerated (a
    // stored-procedure CALL, a DO block, COPY FROM, or an unrecognised node) — the cache must then
    // evict EVERYTHING, not a named set. Deliberately NOT set by SET/PREPARE/BEGIN/COMMIT/SELECT FOR
    // UPDATE/nextval(): those dirty no cached table, so evicting on them would gut the cache.
    let mut opaque_write = false;
    // A positively-identified INSERT/UPDATE/DELETE/MERGE node; paired with the extracted write targets
    // below as a backstop — a DML node seen with no target surfaced falls back to evict-all.
    let mut saw_dml_node = false;
    // Transaction control (BEGIN/COMMIT/…), for the cache's transaction tracking.
    let mut txn_control: Option<TxnControl> = None;

    for stmt in &parsed.protobuf.stmts {
        let Some(node) = stmt.stmt.as_ref().and_then(|n| n.node.as_ref()) else {
            continue;
        };
        match node {
            NodeEnum::SelectStmt(select) => {
                // Row-level locks and SELECT INTO both write, so they leave the replica-safe set.
                if !select.locking_clause.is_empty() || select.into_clause.is_some() {
                    replica_safe = false;
                    saw_write = true;
                    // SELECT ... INTO TEMP creates a temp table -> the session must pin so a later
                    // read that references it does not go to a replica where it does not exist.
                    if into_clause_is_temp(select.into_clause.as_deref()) {
                        pins_session = true;
                    }
                } else {
                    saw_read = true;
                }
            }
            NodeEnum::CreateTableAsStmt(create) => {
                // CREATE [TEMP] TABLE AS / CREATE [TEMP] MATERIALIZED VIEW AS.
                saw_ddl = true;
                replica_safe = false;
                if into_clause_is_temp(create.into.as_deref()) {
                    pins_session = true;
                }
            }
            NodeEnum::ViewStmt(view) => {
                saw_ddl = true;
                replica_safe = false;
                if range_var_is_temp(view.view.as_ref()) {
                    pins_session = true;
                }
            }
            NodeEnum::CreateSeqStmt(seq) => {
                saw_ddl = true;
                replica_safe = false;
                if range_var_is_temp(seq.sequence.as_ref()) {
                    pins_session = true;
                }
            }
            NodeEnum::VariableShowStmt(_) => saw_read = true,
            NodeEnum::VariableSetStmt(_) => {
                replica_safe = false;
                pins_session = true;
            }
            // DISCARD resets state that belongs to one backend: TEMP drops this session's
            // temporary tables, PLANS its cached plans, SEQUENCES its sequence state, ALL of those
            // plus prepared statements, cursors and GUCs. So it must run on the node the session
            // keeps using, and a later read that depends on the reset must not diverge to a replica
            // that never saw it. Previously unmodelled, and so replica-eligible.
            NodeEnum::DiscardStmt(_) => {
                replica_safe = false;
                pins_session = true;
            }
            NodeEnum::PrepareStmt(_)
            | NodeEnum::DeclareCursorStmt(_)
            | NodeEnum::ListenStmt(_)
            | NodeEnum::UnlistenStmt(_)
            | NodeEnum::DeallocateStmt(_) => {
                replica_safe = false;
                pins_session = true;
            }
            NodeEnum::CreateStmt(create) => {
                saw_ddl = true;
                replica_safe = false;
                // A temporary table lives only on its own backend, so the session must pin.
                if create
                    .relation
                    .as_ref()
                    .map(|r| r.relpersistence == "t")
                    .unwrap_or(false)
                {
                    pins_session = true;
                }
            }
            NodeEnum::TransactionStmt(txn) => {
                // Transaction control is routed to the primary/current node by the router.
                replica_safe = false;
                // Use the typed enum (the protobuf enum prepends an UNDEFINED=0 sentinel, so raw ints
                // are +1 from PostgreSQL's C enum). PREPARE TRANSACTION is treated as a commit (apply
                // deferred invalidation conservatively — the prepared txn will commit, maybe elsewhere);
                // SAVEPOINT/RELEASE/ROLLBACK TO/COMMIT-or-ROLLBACK PREPARED do NOT end this transaction.
                use pg_query::protobuf::TransactionStmtKind::*;
                txn_control = Some(match txn.kind() {
                    TransStmtBegin | TransStmtStart => TxnControl::Begin,
                    TransStmtCommit | TransStmtPrepare => TxnControl::Commit { chain: txn.chain },
                    TransStmtRollback => TxnControl::Rollback { chain: txn.chain },
                    TransStmtCommitPrepared => TxnControl::CommitPrepared,
                    _ => TxnControl::Nested,
                });
            }
            NodeEnum::InsertStmt(_)
            | NodeEnum::UpdateStmt(_)
            | NodeEnum::DeleteStmt(_)
            | NodeEnum::MergeStmt(_) => {
                saw_write = true;
                replica_safe = false;
                saw_dml_node = true;
            }
            NodeEnum::CopyStmt(copy) => {
                saw_write = true;
                replica_safe = false;
                // COPY ... FROM bulk-writes its target, which the table extractor does not surface;
                // COPY ... TO is a read but the router already sends every COPY to the primary, so
                // treating the write direction as opaque (evict-all) is consistent and safe.
                if copy.is_from {
                    opaque_write = true;
                }
            }
            // Anything not positively identified as a read is treated as a write. This includes CALL
            // and DO, which run arbitrary DML the parser cannot see into — so evict everything.
            _ => {
                replica_safe = false;
                saw_write = true;
                opaque_write = true;
            }
        }
    }

    let query_type = if saw_ddl {
        QueryType::SchemaChange
    } else if saw_write {
        QueryType::Write
    } else if saw_read {
        QueryType::Read
    } else {
        QueryType::ReadWrite
    };

    // Cache dependency tracking: a read's relations (to record), a write's relations (to evict), and
    // whether a write's targets are unknown (evict everything). A session-state statement (SET, …) is
    // NOT a data write, so it never triggers eviction.
    let mut writes = parsed.dml_tables();
    writes.extend(parsed.ddl_tables());
    writes.sort();
    writes.dedup();
    let reads = if replica_safe {
        parsed.select_tables()
    } else {
        Vec::new()
    };
    // Backstop: a DML node whose target the extractor did not surface (e.g. a grammar shape a future
    // pg_query misses) must evict everything rather than silently keep stale reads.
    if saw_dml_node && writes.is_empty() {
        opaque_write = true;
    }

    SqlAnalysis {
        query_type,
        replica_safe,
        pins_session,
        reads,
        writes,
        opaque_write,
        functions: functions
            .iter()
            .map(|f| f.rsplit('.').next().unwrap_or(f).to_ascii_lowercase())
            .collect(),
        txn: txn_control,
    }
}

/// Keyword-only fallback classifier, used when the grammar parser cannot parse the string.
fn query_type_by_keyword(sql: &str) -> crate::message::QueryType {
    use crate::message::QueryType;
    let first_word = sql
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    match first_word.as_str() {
        "SELECT" | "SHOW" | "FETCH" | "EXPLAIN" | "VALUES" | "TABLE" => QueryType::Read,
        "INSERT" | "UPDATE" | "DELETE" | "COPY" | "MERGE" => QueryType::Write,
        "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "GRANT" | "REVOKE" | "COMMENT" => {
            QueryType::SchemaChange
        }
        _ => QueryType::ReadWrite,
    }
}

/// Analyses the SQL carried by a request frame, if it carries any.
pub fn analyze_frame(frame: &PostgresFrame) -> Option<SqlAnalysis> {
    match frame {
        PostgresFrame::Request(
            FrontendMessage::Query { query } | FrontendMessage::Parse { query, .. },
        ) => Some(analyze_sql(query)),
        _ => None,
    }
}

pub fn query_type(frame: &PostgresFrame) -> crate::message::QueryType {
    analyze_frame(frame)
        .map(|analysis| analysis.query_type)
        .unwrap_or(crate::message::QueryType::ReadWrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::QueryType;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_analyze_reads_are_replica_safe() {
        for sql in [
            "SELECT * FROM orders",
            "SELECT count(*) FROM orders WHERE id > 5",
            "SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.cust",
            "WITH recent AS (SELECT * FROM orders LIMIT 10) SELECT * FROM recent",
            "SHOW server_version",
            "VALUES (1), (2)",
        ] {
            let a = analyze_sql(sql);
            assert!(a.replica_safe, "expected replica-safe: {sql}");
            assert!(!a.pins_session, "expected no session pin: {sql}");
            assert_eq!(a.query_type, QueryType::Read, "{sql}");
        }
    }

    #[test]
    fn test_analyze_writes_and_locks_go_to_primary() {
        // Plain writes.
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1 WHERE id = 2",
            "DELETE FROM t WHERE id = 2",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
        ] {
            let a = analyze_sql(sql);
            assert!(!a.replica_safe, "write must not be replica-safe: {sql}");
            assert_eq!(a.query_type, QueryType::Write, "{sql}");
        }
        // The subtle cases that a keyword classifier gets wrong:
        // a data-modifying CTE under a leading SELECT, and row-locking reads.
        for sql in [
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            "WITH x AS (UPDATE t SET a=1 RETURNING id) SELECT * FROM x",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR SHARE",
            "SELECT nextval('my_seq')",
            "SELECT * INTO new_t FROM t",
        ] {
            let a = analyze_sql(sql);
            assert!(
                !a.replica_safe,
                "hidden write must not be replica-safe: {sql}"
            );
        }
    }

    #[test]
    fn test_analyze_row_locks_anywhere() {
        // Row locks nested in a subquery or CTE are not replica-safe (they error on a replica).
        // This test also pins the LockingClause debug-detection against pg_query format drift.
        for sql in [
            "SELECT * FROM t FOR UPDATE",
            "WITH x AS (SELECT * FROM t FOR UPDATE) SELECT * FROM x",
            "SELECT * FROM (SELECT id FROM t FOR UPDATE) s",
            "SELECT * FROM t WHERE id IN (SELECT id FROM u FOR SHARE)",
        ] {
            assert!(
                !analyze_sql(sql).replica_safe,
                "row lock must not be replica-safe: {sql}"
            );
        }
        // A plain read with the string "for update" in a literal is still replica-safe.
        assert!(analyze_sql("SELECT 'for update' AS note").replica_safe);
    }

    #[test]
    fn test_analyze_writing_functions_go_to_primary() {
        // A SELECT that calls a lock/session/sequence function must not be replica-safe: on a
        // replica it either errors or (worse) silently takes effect on the wrong node.
        for sql in [
            "SELECT pg_advisory_lock(42)",
            "SELECT pg_try_advisory_xact_lock(1, 2)",
            "SELECT pg_advisory_unlock_all()",
            "SELECT set_config('search_path', 'x', false)",
            "SELECT nextval('s')",
            "SELECT currval('s')",
            "SELECT txid_current()",
        ] {
            assert!(
                !analyze_sql(sql).replica_safe,
                "writing function must route to primary: {sql}"
            );
        }
        // An ordinary read-only function is still replica-safe.
        assert!(analyze_sql("SELECT count(*), now(), upper(name) FROM t").replica_safe);
    }

    #[test]
    fn test_analyze_temp_object_creation_pins() {
        for sql in [
            "CREATE TEMP TABLE t AS SELECT 1",
            "SELECT 1 INTO TEMP t",
            "CREATE TEMP VIEW v AS SELECT 1",
            "CREATE TEMP SEQUENCE s",
        ] {
            let a = analyze_sql(sql);
            assert!(a.pins_session, "temp object creation must pin: {sql}");
            assert!(!a.replica_safe, "{sql}");
        }
        // A permanent CREATE TABLE AS is a write/DDL but does not pin the session.
        let permanent = analyze_sql("CREATE TABLE t AS SELECT 1");
        assert!(!permanent.replica_safe);
        assert!(!permanent.pins_session);
    }

    #[test]
    fn test_analyze_ddl_is_schema_change() {
        for sql in [
            "CREATE TABLE t (a int)",
            "ALTER TABLE t ADD COLUMN b int",
            "DROP TABLE t",
        ] {
            let a = analyze_sql(sql);
            assert!(!a.replica_safe, "{sql}");
            assert_eq!(a.query_type, QueryType::SchemaChange, "{sql}");
        }
    }

    #[test]
    fn test_analyze_session_state_pins() {
        for sql in [
            "SET search_path = myschema",
            // set_config() is the function form of SET and must pin identically, or a following
            // replica-safe read diverges to a replica with the old GUC (cross-tenant read).
            "SELECT set_config('search_path', 'tenant_a', false)",
            "SELECT set_config('timezone', 'Asia/Tokyo', true)",
            "PREPARE p AS SELECT 1",
            "LISTEN channel",
            "DECLARE c CURSOR FOR SELECT * FROM t",
            "CREATE TEMP TABLE tmp (a int)",
            // DISCARD's reset is per backend (temp tables, cached plans, sequence state,
            // prepared statements, GUCs), so the session must pin to the node that ran it.
            "DISCARD ALL",
            "DISCARD PLANS",
            "DISCARD TEMP",
        ] {
            let a = analyze_sql(sql);
            assert!(a.pins_session, "expected session pin: {sql}");
            assert!(!a.replica_safe, "{sql}");
        }
    }

    #[test]
    fn test_analyze_unparseable_is_conservative() {
        // Garbage that libpg_query rejects must never be called replica-safe, and — because it could
        // be a write to anything — must invalidate the whole cache.
        let a = analyze_sql("NOT VALID SQL @#$");
        assert!(!a.replica_safe);
        assert!(a.opaque_write);
        assert!(a.writes.is_empty());
    }

    #[test]
    fn test_analyze_cache_dependencies() {
        // A pure read names its tables and is not any kind of write.
        let read = analyze_sql("SELECT id FROM accounts JOIN orders USING (id)");
        assert!(read.reads.contains(&"accounts".to_owned()));
        assert!(read.reads.contains(&"orders".to_owned()));
        assert!(read.writes.is_empty());
        assert!(!read.opaque_write);

        // Named DML surfaces its target for a targeted eviction, and is not opaque.
        for (sql, table) in [
            ("INSERT INTO t (a) VALUES (1)", "t"),
            ("UPDATE t SET a = 1", "t"),
            ("DELETE FROM t WHERE a = 1", "t"),
        ] {
            let a = analyze_sql(sql);
            assert!(a.writes.contains(&table.to_owned()), "{sql} names {table}");
            assert!(!a.opaque_write, "{sql} is not opaque");
            assert!(a.reads.is_empty(), "{sql} caches nothing");
        }

        // A CTE-hidden write is still caught as a named write, not missed.
        let cte = analyze_sql("WITH x AS (INSERT INTO audit VALUES (1) RETURNING *) SELECT * FROM x");
        assert!(cte.writes.contains(&"audit".to_owned()));
        assert!(!cte.opaque_write);

        // Unenumerable writes evict everything: stored-procedure CALL, DO block, COPY FROM.
        for sql in ["CALL do_stuff()", "DO $$ BEGIN END $$", "COPY t FROM STDIN"] {
            assert!(analyze_sql(sql).opaque_write, "{sql} is opaque");
        }

        // COPY ... TO is a read direction — it must NOT evict the whole cache.
        assert!(!analyze_sql("COPY t TO STDOUT").opaque_write);

        // Called functions are surfaced (bare, lowercased) so the cache can judge a read's purity.
        let f = analyze_sql("SELECT COUNT(*), Upper(name) FROM t");
        assert!(f.functions.contains(&"count".to_owned()));
        assert!(f.functions.contains(&"upper".to_owned()));
        assert!(analyze_sql("SELECT log_ev('x')").functions.contains(&"log_ev".to_owned()));
        assert!(analyze_sql("INSERT INTO t VALUES (1)").functions.is_empty());

        // The cache-gutting false positives are excluded: transaction control, row locks, SET, and
        // sequence bumps change no cached table, so they invalidate nothing.
        for sql in [
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SELECT * FROM t FOR UPDATE",
            "SET search_path TO x",
            "SELECT nextval('s')",
        ] {
            let a = analyze_sql(sql);
            assert!(!a.opaque_write, "{sql} must not evict the whole cache");
            assert!(a.writes.is_empty(), "{sql} names no write target");
        }
    }

    #[test]
    fn test_analyze_frame_classifies_query_and_parse() {
        let read = PostgresFrame::Request(FrontendMessage::Query {
            query: "SELECT 1".to_owned(),
        });
        assert_eq!(query_type(&read), QueryType::Read);
        let write = PostgresFrame::Request(FrontendMessage::Parse {
            statement_name: "s".to_owned(),
            query: "DELETE FROM t".to_owned(),
            parameter_data_types: vec![],
        });
        assert_eq!(query_type(&write), QueryType::Write);
        // A non-SQL frame has no analysis.
        assert!(analyze_frame(&PostgresFrame::Request(FrontendMessage::Sync)).is_none());
    }

    fn round_trip(bytes: &[u8], state: PostgresCodecState) -> PostgresFrame {
        let frame = PostgresFrame::from_bytes(Bytes::copy_from_slice(bytes), state).unwrap();
        let mut encoded = BytesMut::new();
        frame.clone().encode(&mut encoded).unwrap();
        assert_eq!(bytes, &encoded, "round trip of {frame}");
        frame
    }

    /// A startup message as sent by psql: protocol 3.0, user and database parameters.
    #[test]
    fn test_startup_round_trip() {
        let mut bytes = BytesMut::new();
        FrontendMessage::Startup {
            protocol_version: 196608,
            parameters: vec![
                ("user".to_owned(), "admin".to_owned()),
                ("database".to_owned(), "lakehouse_poc_sim".to_owned()),
                ("application_name".to_owned(), "psql".to_owned()),
                ("client_encoding".to_owned(), "UTF8".to_owned()),
            ],
        }
        .encode(&mut bytes)
        .unwrap();
        let frame = round_trip(&bytes, PostgresCodecState::request(true));
        match frame {
            PostgresFrame::Request(FrontendMessage::Startup {
                protocol_version,
                parameters,
            }) => {
                assert_eq!(protocol_version, 196608);
                assert_eq!(parameters[0], ("user".to_owned(), "admin".to_owned()));
            }
            other => panic!("expected Startup, got {other:?}"),
        }
    }

    #[test]
    fn test_cancel_request_round_trip() {
        let mut bytes = BytesMut::new();
        FrontendMessage::CancelRequest {
            process_id: 1234,
            secret_key: Bytes::from_static(&[1, 2, 3, 4]),
        }
        .encode(&mut bytes)
        .unwrap();
        assert_eq!(bytes.len(), 16);
        round_trip(&bytes, PostgresCodecState::request(true));
    }

    #[test]
    fn test_simple_query_round_trip() {
        // "Q" length=25, "SELECT 1;\0" style message captured shape
        let mut bytes = BytesMut::new();
        FrontendMessage::Query {
            query: "SELECT * FROM bronze.company".to_owned(),
        }
        .encode(&mut bytes)
        .unwrap();
        let frame = round_trip(&bytes, PostgresCodecState::request(false));
        assert_eq!(crate::message::QueryType::Read, query_type(&frame));
    }

    #[test]
    fn test_extended_query_round_trip() {
        let mut bytes = BytesMut::new();
        FrontendMessage::Parse {
            statement_name: "s1".to_owned(),
            query: "INSERT INTO t VALUES ($1, $2)".to_owned(),
            parameter_data_types: vec![23, 25],
        }
        .encode(&mut bytes)
        .unwrap();
        let frame = round_trip(&bytes, PostgresCodecState::request(false));
        assert_eq!(crate::message::QueryType::Write, query_type(&frame));

        let mut bytes = BytesMut::new();
        FrontendMessage::Bind {
            portal_name: "".to_owned(),
            statement_name: "s1".to_owned(),
            parameter_format_codes: vec![0, 1],
            parameter_values: vec![Some(Bytes::from_static(b"42")), None],
            result_format_codes: vec![0],
        }
        .encode(&mut bytes)
        .unwrap();
        round_trip(&bytes, PostgresCodecState::request(false));

        for message in [
            FrontendMessage::Describe {
                kind: b'P',
                name: "".to_owned(),
            },
            FrontendMessage::Execute {
                portal_name: "".to_owned(),
                max_rows: 0,
            },
            FrontendMessage::Sync,
            FrontendMessage::Flush,
            FrontendMessage::Close {
                kind: b'S',
                name: "s1".to_owned(),
            },
            FrontendMessage::Terminate,
        ] {
            let mut bytes = BytesMut::new();
            message.encode(&mut bytes).unwrap();
            round_trip(&bytes, PostgresCodecState::request(false));
        }
    }

    /// The full response train to a simple SELECT: RowDescription, DataRows, CommandComplete, ReadyForQuery.
    #[test]
    fn test_query_response_train_round_trip() {
        let mut bytes = BytesMut::new();
        for message in [
            BackendMessage::RowDescription {
                fields: vec![
                    FieldDescription {
                        name: "company_id".to_owned(),
                        table_oid: 16384,
                        column_attribute_number: 1,
                        data_type_oid: 23,
                        data_type_size: 4,
                        type_modifier: -1,
                        format_code: 0,
                    },
                    FieldDescription {
                        name: "company_name".to_owned(),
                        table_oid: 16384,
                        column_attribute_number: 2,
                        data_type_oid: 25,
                        data_type_size: -1,
                        type_modifier: -1,
                        format_code: 0,
                    },
                ],
            },
            BackendMessage::DataRow {
                values: vec![
                    Some(Bytes::from_static(b"300")),
                    Some(Bytes::from_static(b"Meridian Moulding Group")),
                ],
            },
            BackendMessage::DataRow {
                values: vec![Some(Bytes::from_static(b"400")), None],
            },
            BackendMessage::CommandComplete {
                tag: "SELECT 2".to_owned(),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ] {
            message.encode(&mut bytes).unwrap();
        }
        let frame = round_trip(&bytes, PostgresCodecState::response());
        match &frame {
            PostgresFrame::Response(messages) => {
                assert_eq!(messages.len(), 5);
                assert_eq!(
                    format!("{frame}"),
                    "Response[RowDescription, DataRow x2, CommandComplete, ReadyForQuery]"
                );
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// The startup response train: AuthenticationOk, ParameterStatus*, BackendKeyData, ReadyForQuery.
    #[test]
    fn test_startup_response_train_round_trip() {
        let mut bytes = BytesMut::new();
        for message in [
            BackendMessage::Authentication(AuthenticationMessage::Ok),
            BackendMessage::ParameterStatus {
                name: "server_version".to_owned(),
                value: "18.0".to_owned(),
            },
            BackendMessage::ParameterStatus {
                name: "client_encoding".to_owned(),
                value: "UTF8".to_owned(),
            },
            BackendMessage::BackendKeyData {
                process_id: 4242,
                secret_key: Bytes::from_static(&[9, 9, 9, 9]),
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ] {
            message.encode(&mut bytes).unwrap();
        }
        round_trip(&bytes, PostgresCodecState::response());
    }

    /// SASL authentication messages: SCRAM-SHA-256 offer, continue, final.
    #[test]
    fn test_sasl_round_trip() {
        let mut bytes = BytesMut::new();
        BackendMessage::Authentication(AuthenticationMessage::Sasl {
            mechanisms: vec!["SCRAM-SHA-256".to_owned()],
        })
        .encode(&mut bytes)
        .unwrap();
        let frame = round_trip(&bytes, PostgresCodecState::response());
        match frame {
            PostgresFrame::Response(messages) => match &messages[0] {
                BackendMessage::Authentication(AuthenticationMessage::Sasl { mechanisms }) => {
                    assert_eq!(mechanisms, &["SCRAM-SHA-256".to_owned()]);
                }
                other => panic!("expected Sasl, got {other:?}"),
            },
            other => panic!("expected Response, got {other:?}"),
        }

        let mut bytes = BytesMut::new();
        BackendMessage::Authentication(AuthenticationMessage::SaslContinue {
            data: Bytes::from_static(b"r=nonce,s=salt,i=4096"),
        })
        .encode(&mut bytes)
        .unwrap();
        round_trip(&bytes, PostgresCodecState::response());

        let mut bytes = BytesMut::new();
        FrontendMessage::AuthenticationData(Bytes::from_static(b"n,,n=,r=clientnonce"))
            .encode(&mut bytes)
            .unwrap();
        round_trip(&bytes, PostgresCodecState::request(false));
    }

    #[test]
    fn test_error_response_round_trip() {
        let mut bytes = BytesMut::new();
        for message in [
            BackendMessage::ErrorResponse {
                fields: vec![
                    (b'S', "ERROR".to_owned()),
                    (b'V', "ERROR".to_owned()),
                    (b'C', "42P01".to_owned()),
                    (b'M', "relation \"missing\" does not exist".to_owned()),
                ],
            },
            BackendMessage::ReadyForQuery { status: b'I' },
        ] {
            message.encode(&mut bytes).unwrap();
        }
        let frame = round_trip(&bytes, PostgresCodecState::response());
        match frame {
            PostgresFrame::Response(messages) => {
                assert_eq!(
                    messages[0].error_message(),
                    Some("relation \"missing\" does not exist")
                );
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn test_copy_round_trip() {
        let mut bytes = BytesMut::new();
        BackendMessage::CopyInResponse {
            overall_format: 0,
            column_formats: vec![0, 0, 0],
        }
        .encode(&mut bytes)
        .unwrap();
        round_trip(&bytes, PostgresCodecState::response());

        let mut bytes = BytesMut::new();
        for message in [
            FrontendMessage::CopyData(Bytes::from_static(b"1\ttext value\n")),
            FrontendMessage::CopyDone,
        ] {
            message.encode(&mut bytes).unwrap();
            let length = message_wire_length(&bytes, false).unwrap().unwrap();
            let message_bytes = bytes.split_to(length);
            round_trip(&message_bytes, PostgresCodecState::request(false));
        }

        let mut bytes = BytesMut::new();
        FrontendMessage::CopyFail {
            message: "client aborted".to_owned(),
        }
        .encode(&mut bytes)
        .unwrap();
        round_trip(&bytes, PostgresCodecState::request(false));
    }

    /// An unknown tag must parse to Raw and round trip byte identically.
    #[test]
    fn test_unknown_tag_raw_round_trip() {
        let mut bytes = BytesMut::new();
        bytes.put_u8(b'!');
        bytes.put_i32(9);
        bytes.extend_from_slice(b"weird");
        let frame = round_trip(&bytes, PostgresCodecState::request(false));
        match frame {
            PostgresFrame::Request(FrontendMessage::Raw { tag, body }) => {
                assert_eq!(tag, b'!');
                assert_eq!(&body[..], b"weird");
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    /// A message with a corrupt inner layout (but valid framing) must degrade to Raw, not error.
    #[test]
    fn test_corrupt_body_degrades_to_raw() {
        // A 'T' RowDescription whose declared field count exceeds the body length.
        let mut bytes = BytesMut::new();
        bytes.put_u8(b'T');
        bytes.put_i32(6);
        bytes.put_i16(999);
        let frame = round_trip(&bytes, PostgresCodecState::response());
        match frame {
            PostgresFrame::Response(messages) => {
                assert!(matches!(messages[0], BackendMessage::Raw { tag: b'T', .. }));
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    /// Bogus startup length must hard error: this is how a non postgres client is rejected.
    #[test]
    fn test_garbage_startup_rejected() {
        // A TLS ClientHello starts with 0x16 0x03 which produces a nonsense length.
        let bytes = [0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01];
        assert!(message_wire_length(&bytes, true).is_err());
    }
}
