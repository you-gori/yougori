//! A minimal GraphQL executable-document reader (VM part §4.6 line 2024: GraphQL can
//! carry many operations).
//!
//! It only finds the top-level definitions of a document: the operations, with their
//! kind and name, and the fragments. Selection sets are skipped by balanced braces, and
//! strings, block strings and comments are lexed so that braces inside them do not
//! count. Type-system definitions are refused, since they are not executable. It does
//! not validate a document against a schema.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Largest document read.
pub const MAX_GRAPHQL_DOCUMENT_BYTES: usize = 64 * 1024;
/// Deepest brace or parenthesis nesting read.
pub const MAX_GRAPHQL_DEPTH: usize = 64;

/// The kind of a parsed operation definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphQlParsedKind {
    Query,
    Mutation,
    Subscription,
}

/// One operation definition at the top level of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphQlOperationHead {
    pub kind: GraphQlParsedKind,
    /// `None` for an anonymous operation, including the `{ ... }` shorthand.
    pub name: Option<String>,
}

/// The top-level definitions of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphQlSummary {
    pub operations: Vec<GraphQlOperationHead>,
    pub fragments: usize,
}

strict_provider_enum! {
    /// Why a document was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum GraphQlRefusal tag "refusal" {
        TooLarge { max_bytes: u64 },
        TooDeep { max_depth: u64 },
        /// A character or token that cannot start or continue a definition here.
        Malformed { at_byte: u64 },
        Unterminated,
        /// A schema or type definition: not an executable operation.
        TypeSystemDefinition,
        /// The document holds this many operations; exactly one is accepted.
        NotExactlyOneOperation { operations: u64 },
        AnonymousOperation,
        SubscriptionNotAccepted,
        /// The operation's name or kind differs from the registered contract's.
        OperationMismatch,
        /// The document's digest differs from the registered document.
        DocumentMismatch,
    }
}

impl fmt::Display for GraphQlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => write!(f, "the document is above {max_bytes} bytes"),
            Self::TooDeep { max_depth } => write!(f, "the document nests deeper than {max_depth}"),
            Self::Malformed { at_byte } => write!(f, "the document is malformed at byte {at_byte}"),
            Self::Unterminated => f.write_str("the document ends inside a string or block"),
            Self::TypeSystemDefinition => {
                f.write_str("type-system definitions are not executable operations")
            }
            Self::NotExactlyOneOperation { operations } => write!(
                f,
                "the document holds {operations} operations; one typed contract covers exactly \
                 one named operation"
            ),
            Self::AnonymousOperation => f.write_str("the operation must be named"),
            Self::SubscriptionNotAccepted => {
                f.write_str("subscriptions are streams, not one bounded operation")
            }
            Self::OperationMismatch => {
                f.write_str("the operation's name or kind differs from its contract")
            }
            Self::DocumentMismatch => f.write_str("the document differs from the registered one"),
        }
    }
}

impl std::error::Error for GraphQlRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
    Punct(u8),
    Other,
}

fn at(index: usize) -> GraphQlRefusal {
    GraphQlRefusal::Malformed {
        at_byte: u64::try_from(index).unwrap_or(u64::MAX),
    }
}

fn is_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_name_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn tokenize(document: &str) -> Result<Vec<Token>, GraphQlRefusal> {
    let bytes = document.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' | b',' => index = index.saturating_add(1),
            b'#' => {
                while let Some(&next) = bytes.get(index) {
                    if next == b'\n' || next == b'\r' {
                        break;
                    }
                    index = index.saturating_add(1);
                }
            }
            b'"' => {
                index = if bytes.get(index..index.saturating_add(3)) == Some(b"\"\"\"") {
                    skip_block_string(bytes, index.saturating_add(3))?
                } else {
                    skip_string(bytes, index.saturating_add(1))?
                };
                tokens.push(Token::Other);
            }
            b'.' => {
                if bytes.get(index..index.saturating_add(3)) != Some(b"...") {
                    return Err(at(index));
                }
                index = index.saturating_add(3);
                tokens.push(Token::Other);
            }
            b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'}'
            | b'|' => {
                tokens.push(Token::Punct(byte));
                index = index.saturating_add(1);
            }
            _ if is_name_start(byte) => {
                let start = index;
                while bytes.get(index).is_some_and(|&next| is_name_continue(next)) {
                    index = index.saturating_add(1);
                }
                let name = document.get(start..index).ok_or_else(|| at(start))?;
                tokens.push(Token::Name(name.to_owned()));
            }
            b'-' | b'0'..=b'9' => {
                index = index.saturating_add(1);
                while bytes.get(index).is_some_and(|&next| {
                    next.is_ascii_digit() || matches!(next, b'.' | b'e' | b'E' | b'+' | b'-')
                }) {
                    index = index.saturating_add(1);
                }
                tokens.push(Token::Other);
            }
            // A byte-order mark at the start is ignored, as the specification allows.
            0xEF if index == 0 && bytes.get(0..3) == Some(&[0xEF, 0xBB, 0xBF][..]) => index = 3,
            _ => return Err(at(index)),
        }
    }
    Ok(tokens)
}

fn skip_string(bytes: &[u8], mut index: usize) -> Result<usize, GraphQlRefusal> {
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => return Ok(index.saturating_add(1)),
            b'\\' => index = index.saturating_add(2),
            b'\n' | b'\r' => return Err(at(index)),
            _ => index = index.saturating_add(1),
        }
    }
    Err(GraphQlRefusal::Unterminated)
}

fn skip_block_string(bytes: &[u8], mut index: usize) -> Result<usize, GraphQlRefusal> {
    while index < bytes.len() {
        if bytes.get(index..index.saturating_add(4)) == Some(b"\\\"\"\"") {
            index = index.saturating_add(4);
        } else if bytes.get(index..index.saturating_add(3)) == Some(b"\"\"\"") {
            return Ok(index.saturating_add(3));
        } else {
            index = index.saturating_add(1);
        }
    }
    Err(GraphQlRefusal::Unterminated)
}

/// Skips a balanced group that opens at `tokens[index]` with `open` and returns the index
/// after its close.
fn skip_group(
    tokens: &[Token],
    index: usize,
    open: u8,
    close: u8,
) -> Result<usize, GraphQlRefusal> {
    let mut depth = 0usize;
    let mut cursor = index;
    while let Some(token) = tokens.get(cursor) {
        if *token == Token::Punct(open) {
            depth = depth.saturating_add(1);
            if depth > MAX_GRAPHQL_DEPTH {
                return Err(GraphQlRefusal::TooDeep {
                    max_depth: u64::try_from(MAX_GRAPHQL_DEPTH).unwrap_or(u64::MAX),
                });
            }
        } else if *token == Token::Punct(close) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Ok(cursor.saturating_add(1));
            }
        }
        cursor = cursor.saturating_add(1);
    }
    Err(GraphQlRefusal::Unterminated)
}

/// Skips variable definitions and directives up to the selection set, then the selection
/// set, and returns the index after it.
fn skip_to_selection_end(tokens: &[Token], mut index: usize) -> Result<usize, GraphQlRefusal> {
    loop {
        match tokens.get(index) {
            Some(Token::Punct(b'{')) => return skip_group(tokens, index, b'{', b'}'),
            Some(Token::Punct(b'(')) => index = skip_group(tokens, index, b'(', b')')?,
            Some(Token::Punct(b'}')) | Some(Token::Punct(b')')) => return Err(at(index)),
            Some(_) => index = index.saturating_add(1),
            None => return Err(GraphQlRefusal::Unterminated),
        }
    }
}

const TYPE_SYSTEM_KEYWORDS: [&str; 9] = [
    "schema",
    "scalar",
    "type",
    "interface",
    "union",
    "enum",
    "input",
    "directive",
    "extend",
];

/// Reads the top-level definitions of `document`.
pub fn summarize_document(document: &str) -> Result<GraphQlSummary, GraphQlRefusal> {
    if document.len() > MAX_GRAPHQL_DOCUMENT_BYTES {
        return Err(GraphQlRefusal::TooLarge {
            max_bytes: u64::try_from(MAX_GRAPHQL_DOCUMENT_BYTES).unwrap_or(u64::MAX),
        });
    }
    let tokens = tokenize(document)?;
    let mut operations = Vec::new();
    let mut fragments = 0usize;
    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        match token {
            Token::Punct(b'{') => {
                operations.push(GraphQlOperationHead {
                    kind: GraphQlParsedKind::Query,
                    name: None,
                });
                index = skip_group(&tokens, index, b'{', b'}')?;
            }
            Token::Name(word) if matches!(word.as_str(), "query" | "mutation" | "subscription") => {
                let kind = match word.as_str() {
                    "query" => GraphQlParsedKind::Query,
                    "mutation" => GraphQlParsedKind::Mutation,
                    _ => GraphQlParsedKind::Subscription,
                };
                index = index.saturating_add(1);
                let name = match tokens.get(index) {
                    Some(Token::Name(name)) => {
                        index = index.saturating_add(1);
                        Some(name.clone())
                    }
                    _ => None,
                };
                operations.push(GraphQlOperationHead { kind, name });
                index = skip_to_selection_end(&tokens, index)?;
            }
            Token::Name(word) if word == "fragment" => {
                fragments = fragments.saturating_add(1);
                index = skip_to_selection_end(&tokens, index.saturating_add(1))?;
            }
            Token::Name(word) if TYPE_SYSTEM_KEYWORDS.contains(&word.as_str()) => {
                return Err(GraphQlRefusal::TypeSystemDefinition)
            }
            _ => return Err(at(index)),
        }
    }
    Ok(GraphQlSummary {
        operations,
        fragments,
    })
}

/// The one named operation of `document`, or why there is not exactly one.
pub(super) fn single_named_operation(
    document: &str,
) -> Result<(GraphQlParsedKind, String), GraphQlRefusal> {
    let summary = summarize_document(document)?;
    let [head] = summary.operations.as_slice() else {
        return Err(GraphQlRefusal::NotExactlyOneOperation {
            operations: u64::try_from(summary.operations.len()).unwrap_or(u64::MAX),
        });
    };
    if head.kind == GraphQlParsedKind::Subscription {
        return Err(GraphQlRefusal::SubscriptionNotAccepted);
    }
    let name = head
        .name
        .clone()
        .ok_or(GraphQlRefusal::AnonymousOperation)?;
    Ok((head.kind, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(document: &str) -> usize {
        summarize_document(document).unwrap().operations.len()
    }

    #[test]
    fn one_named_operation_is_found_with_its_kind() {
        let document = "query GetRepo($owner: String!) { repository(owner: $owner) { id } }";
        assert_eq!(
            single_named_operation(document),
            Ok((GraphQlParsedKind::Query, "GetRepo".to_owned()))
        );
        let mutation = "mutation AddStar($id: ID!) @client { addStar(input: {starrableId: $id}) { clientMutationId } }";
        assert_eq!(
            single_named_operation(mutation),
            Ok((GraphQlParsedKind::Mutation, "AddStar".to_owned()))
        );
    }

    #[test]
    fn more_than_one_operation_is_refused() {
        let two = "query A { a } mutation B { b }";
        assert_eq!(count(two), 2);
        assert_eq!(
            single_named_operation(two),
            Err(GraphQlRefusal::NotExactlyOneOperation { operations: 2 })
        );
        // A shorthand query next to a named one is still two operations.
        assert_eq!(
            single_named_operation("{ a } query B { b }"),
            Err(GraphQlRefusal::NotExactlyOneOperation { operations: 2 })
        );
        assert_eq!(
            single_named_operation(""),
            Err(GraphQlRefusal::NotExactlyOneOperation { operations: 0 })
        );
    }

    #[test]
    fn braces_in_strings_comments_and_arguments_do_not_hide_operations() {
        let document = r#"
            # mutation Hidden { x }
            query A($f: In = {nested: {deep: "}"}}) {
              a(text: "} mutation Evil { e } {", block: """ } query X { y } \""" """) { b }
            }
            mutation Second { s }
        "#;
        let summary = summarize_document(document).unwrap();
        assert_eq!(summary.operations.len(), 2);
        assert_eq!(summary.operations[1].name.as_deref(), Some("Second"));
    }

    #[test]
    fn fragments_are_not_operations_and_type_definitions_are_refused() {
        let document = "query A { ...F } fragment F on Repo { id }";
        let summary = summarize_document(document).unwrap();
        assert_eq!((summary.operations.len(), summary.fragments), (1, 1));
        assert_eq!(
            summarize_document("type Repo { id: ID }"),
            Err(GraphQlRefusal::TypeSystemDefinition)
        );
    }

    #[test]
    fn anonymous_and_subscription_operations_are_refused() {
        assert_eq!(
            single_named_operation("{ a }"),
            Err(GraphQlRefusal::AnonymousOperation)
        );
        assert_eq!(
            single_named_operation("query { a }"),
            Err(GraphQlRefusal::AnonymousOperation)
        );
        assert_eq!(
            single_named_operation("subscription S { a }"),
            Err(GraphQlRefusal::SubscriptionNotAccepted)
        );
    }

    #[test]
    fn malformed_unterminated_deep_and_large_documents_are_refused() {
        assert!(matches!(
            summarize_document("query A { a } }"),
            Err(GraphQlRefusal::Malformed { .. })
        ));
        assert_eq!(
            summarize_document("query A { a "),
            Err(GraphQlRefusal::Unterminated)
        );
        assert_eq!(
            summarize_document(
                "query A { a(t: \"open
) }"
            ),
            Err(GraphQlRefusal::Malformed { at_byte: 20 })
        );
        let deep = format!("query A {}{}", "{".repeat(70), "}".repeat(70));
        assert_eq!(
            summarize_document(&deep),
            Err(GraphQlRefusal::TooDeep { max_depth: 64 })
        );
        let large = format!(
            "query A {{ a }} #{}",
            "x".repeat(MAX_GRAPHQL_DOCUMENT_BYTES)
        );
        assert_eq!(
            summarize_document(&large),
            Err(GraphQlRefusal::TooLarge {
                max_bytes: MAX_GRAPHQL_DOCUMENT_BYTES as u64
            })
        );
        assert!(matches!(
            summarize_document("query A { a } ;"),
            Err(GraphQlRefusal::Malformed { .. })
        ));
    }

    #[test]
    fn refusals_round_trip_strictly() {
        let refusal = GraphQlRefusal::NotExactlyOneOperation { operations: 2 };
        let json = serde_json::to_string(&refusal).unwrap();
        assert_eq!(
            serde_json::from_str::<GraphQlRefusal>(&json).unwrap(),
            refusal
        );
        assert!(serde_json::from_str::<GraphQlRefusal>(
            r#"{"refusal":"anonymous_operation","extra":1}"#
        )
        .is_err());
    }
}
