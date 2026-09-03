#[cfg(feature = "alpha-transforms")]
pub mod read_cache;
#[cfg(feature = "alpha-transforms")]
pub mod redact_column;
pub mod sink_cluster;
pub mod sink_single;

use crate::codec::postgres::is_partial_response;
use crate::connection::SinkConnection;
use crate::frame::Frame;
use crate::frame::postgres::{FrontendMessage, PostgresFrame};
use crate::message::{Message, Messages};
use anyhow::Result;
use std::time::Duration;

/// A backend accepted the connection but did not produce the next response within `read_timeout`.
/// Typed so a sink can turn it into a client ErrorResponse + connection close rather than letting the
/// client hang forever on a backend that stalls mid-answer.
#[derive(Debug)]
pub(crate) struct BackendReadTimeout;

impl std::fmt::Display for BackendReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "postgres backend did not respond within read_timeout")
    }
}

impl std::error::Error for BackendReadTimeout {}

/// Returns true if a request makes the server produce output now.
///
/// The extended-query messages (Parse/Bind/Describe/Execute/Close) produce NO output until the
/// server sees a Flush or Sync — it buffers their responses. Everything else here elicits an
/// immediate response: the startup/auth exchange, a simple Query, Sync, Flush, and the COPY
/// terminators. An unparseable or non-postgres request is assumed to elicit a response so that a
/// batch is never mistaken for a buffered one (which would hang).
fn request_triggers_flush(request: &mut Message) -> bool {
    match request.frame() {
        Some(Frame::Postgres(PostgresFrame::Request(message))) => matches!(
            message,
            FrontendMessage::Startup { .. }
                | FrontendMessage::AuthenticationData(_)
                | FrontendMessage::Query { .. }
                | FrontendMessage::Sync
                | FrontendMessage::Flush
                | FrontendMessage::CopyDone
                | FrontendMessage::CopyFail { .. }
                | FrontendMessage::CancelRequest { .. }
        ),
        _ => true,
    }
}

/// The number of trailing requests in a batch that CANNOT be answered yet.
///
/// Postgres flushes only what PRECEDES a flush point, so it is not enough to ask whether a batch
/// contains a flush point — a batch like `[Query, Parse]` or `[Sync, Parse]` flushes the Query/Sync
/// but buffers the trailing Parse until the next Flush/Sync. Blocking for that Parse's response
/// deadlocks (and swallows the Query's response with it), which is a TCP-coalescing shape a client
/// hits under load. This returns how many requests sit AFTER the last flush point, so the caller can
/// wait for everything up to and including that flush point and leave the trailing partial pipeline
/// outstanding for the next batch. `None` means the batch has no flush point at all — nothing it
/// sent can be answered until a later batch carries one.
fn trailing_unanswerable(requests: &mut [Message]) -> Option<usize> {
    requests
        .iter_mut()
        .rposition(request_triggers_flush)
        .map(|last_flush| requests.len() - 1 - last_flush)
}

/// How many response batches a STREAMING postgres sink lets its backend run ahead of the chain.
///
/// It has to be small for a bounded client channel to mean anything: a chain that stops draining
/// because the client is slow would otherwise just fill this queue with the rest of the result.
///
/// Sizing, and it is NOT one chunk per batch downstream: `SinkConnection::recv_into` exhausts this
/// queue before returning, so one chain run coalesces everything queued here into a SINGLE batch
/// for the client channel. A client-channel slot therefore holds up to this many chunks, and the
/// ceiling for a streaming connection is about `(response_buffer_batches * this + this) *
/// stream_threshold_bytes` — not the sum of the two bounds.
pub(crate) const STREAMING_RESPONSE_BUFFER_BATCHES: usize = 8;

/// Waits for more of a backend's response, under the idle timeout the sink configured.
///
/// `read_timeout` is a true IDLE timeout: `recv_into_or_idle_timeout` resets the clock on every
/// inbound socket chunk (`SinkConnection` stamps activity BELOW the frame layer, so a whole response
/// train's progress is visible), so a large continuously-streaming result is never cut off — only a
/// backend that produces nothing for the whole timeout trips it. Unset means wait forever, which is
/// the documented default.
pub(crate) async fn recv_under_idle_timeout(
    connection: &mut SinkConnection,
    responses: &mut Messages,
    read_timeout: Option<Duration>,
) -> Result<()> {
    match read_timeout {
        Some(timeout) => {
            if !connection
                .recv_into_or_idle_timeout(responses, timeout)
                .await?
            {
                return Err(BackendReadTimeout.into());
            }
        }
        None => connection.recv_into(responses).await?,
    }
    Ok(())
}

/// Sends one batch of requests to a backend and reads the responses the server produces for it.
///
/// `outstanding` tracks requests still awaiting a response ACROSS batches (each request eventually
/// yields exactly one response — a real one, or a dummy generated by the connection for messages the
/// server never answers). The caller blocks only for the responses the server will actually flush
/// for this batch — everything up to and including its last flush point — and leaves any trailing
/// partial pipeline outstanding for the batch that carries the next flush point. A batch with no
/// flush point at all does not block: its responses arrive later.
///
/// It may also return with a response train still arriving, rather than holding a whole large
/// result here — see [`train_in_flight`], which is how a caller must decide that, never by which
/// path this took.
pub(crate) async fn exchange(
    connection: &mut SinkConnection,
    mut requests: Messages,
    outstanding: &mut usize,
    read_timeout: Option<Duration>,
) -> Result<Messages> {
    let trailing = trailing_unanswerable(&mut requests);
    *outstanding += requests.len();
    connection.send(requests)?;

    let mut responses = vec![];
    match trailing {
        // The batch has a flush point: drain everything except the trailing partial pipeline.
        Some(trailing) => {
            while *outstanding > trailing {
                recv_and_account(connection, &mut responses, outstanding, read_timeout).await?;
                // Hand chunks up the chain as they arrive instead of holding the whole train here.
                if train_in_flight(&responses) {
                    return Ok(responses);
                }
            }
        }
        // No flush point: grab any responses already available (e.g. the dummy responses the
        // connection generates for CopyData) but do not block on the server.
        None => {
            let _ = connection.try_recv_into(&mut responses);
            *outstanding = outstanding.saturating_sub(count_answered(&responses));
        }
    }
    Ok(responses)
}

/// Receives more of a response and reconciles `outstanding` with what arrived.
///
/// Both halves or neither: a response that answers a request but goes uncounted leaves
/// `outstanding` high, and the next [`exchange`] then blocks for a reply already delivered.
pub(crate) async fn recv_and_account(
    connection: &mut SinkConnection,
    responses: &mut Messages,
    outstanding: &mut usize,
    read_timeout: Option<Duration>,
) -> Result<()> {
    let before = responses.len();
    recv_under_idle_timeout(connection, responses, read_timeout).await?;
    *outstanding = outstanding.saturating_sub(count_answered(&responses[before..]));
    Ok(())
}

/// Whether a response train is still arriving, judged from what was actually received: the last
/// message in hand is one of its chunks.
///
/// This is the ONLY safe test. A train's chunks carry no request id and only its final message
/// does, so "the last message is a partial" is exactly "more of this train is coming". Deriving it
/// any other way has been wrong every time it was tried: counting id-carrying responses breaks when
/// one receive delivers the end of one train and the start of the next, and asking which code path
/// ran breaks when a batch with no flush point is sent while a train is still arriving.
pub(crate) fn train_in_flight(responses: &[Message]) -> bool {
    responses.last().is_some_and(is_partial_response)
}

/// The number of responses that answer a request (i.e. carry a request id). Unrequested responses
/// (asynchronous notices, parameter-status changes, notifications) do not decrement `outstanding`.
pub(crate) fn count_answered(responses: &[Message]) -> usize {
    responses
        .iter()
        .filter(|r| r.request_id().is_some())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(message: FrontendMessage) -> Message {
        Message::from_frame(Frame::Postgres(PostgresFrame::Request(message)))
    }

    fn query() -> FrontendMessage {
        FrontendMessage::Query {
            query: "SELECT 1".to_owned(),
        }
    }

    fn parse() -> FrontendMessage {
        FrontendMessage::Parse {
            statement_name: "".to_owned(),
            query: "SELECT 1".to_owned(),
            parameter_data_types: vec![],
        }
    }

    fn bind() -> FrontendMessage {
        FrontendMessage::Bind {
            portal_name: "".to_owned(),
            statement_name: "".to_owned(),
            parameter_format_codes: vec![],
            parameter_values: vec![],
            result_format_codes: vec![],
        }
    }

    fn batch(messages: Vec<FrontendMessage>) -> Vec<Message> {
        messages.into_iter().map(req).collect()
    }

    #[test]
    fn test_trailing_unanswerable() {
        // A flush point at the end: nothing trailing, drain everything.
        assert_eq!(trailing_unanswerable(&mut batch(vec![query()])), Some(0));
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![parse(), FrontendMessage::Sync])),
            Some(0)
        );
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![parse(), query()])),
            Some(0)
        );
        // A flush point followed by a buffered pipeline: those trailing messages cannot answer yet.
        // These are the coalesced-pipeline shapes that deadlocked the round-two fix.
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![query(), parse()])),
            Some(1)
        );
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![FrontendMessage::Sync, parse()])),
            Some(1)
        );
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![FrontendMessage::Sync, parse(), bind()])),
            Some(2)
        );
        // No flush point at all: the whole batch is buffered, do not block.
        assert_eq!(trailing_unanswerable(&mut batch(vec![parse()])), None);
        assert_eq!(
            trailing_unanswerable(&mut batch(vec![parse(), bind()])),
            None
        );
    }
}
