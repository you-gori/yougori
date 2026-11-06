//! Typed remote argv and the one encoder for the remote POSIX shell (VM-W41: "command
//! arguments cannot become shell programs"; VM part §4.5: no secret copies in command
//! arguments; VM-D14).
//!
//! SSH hands the remote account's login shell one command string, so every remote
//! command is shell text in the end. Here a command is built only from a checked program
//! path, flags that are `'static` text, and operands of any text but NUL, and it becomes
//! shell text only through [`encode_posix`], which single-quotes every word. There is
//! no API that takes command text or joins strings into a command, and an
//! [`EncodedCommand`] cannot be made from a string. The quoting is POSIX shell quoting:
//! the management identity refuses any other login shell.
//!
//! An operand that begins with `-` could still be read as an option by the program. A
//! program declared to accept `--` gets it before its first operand; for one that does
//! not, such an operand is refused.
//!
//! Secrets never go into argv: a [`RemoteSecret`] has no conversion to text or to an
//! operand. Typed operations such as [`replace_jupyter_password`] pass the value over
//! stdin, and check the encoded command for the secret before returning it.

use std::fmt;

use serde::Serialize;

use super::ssh::{
    ExecutionContext, KnownHosts, ManagementAction, ManagementIdentity, ManagementRefusal,
};
use crate::sandbox_contract::provider::find_encoded;

/// Longest operand accepted: Linux's per-argument limit, `MAX_ARG_STRLEN`.
pub const MAX_REMOTE_ARG_BYTES: usize = 128 * 1024;
/// Longest program path accepted.
pub const MAX_PROGRAM_PATH_BYTES: usize = 4_096;
/// Longest encoded command accepted, well inside a remote `ARG_MAX`.
pub const MAX_ENCODED_COMMAND_BYTES: usize = 1024 * 1024;
/// Bound for one management request sent through authenticated stdin.
pub const MAX_REMOTE_STDIN_BYTES: usize = 1024 * 1024;
/// The shortest replacement Jupyter password accepted (VM-D14).
pub const MIN_JUPYTER_PASSWORD_BYTES: usize = 16;

strict_remote_enum! {
    /// Why a remote command or invocation was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ArgvRefusal tag "kind" {
        /// A program is an absolute path of letters, digits, '.', '_', '+', '-' and '/',
        /// without empty, '.' or '..' components.
        InvalidProgram,
        /// NUL cannot be passed in an argument.
        NulInArgument,
        ArgumentTooLong { max_bytes: u64 },
        /// A flag is '-' or '--' followed by letters, digits, '-', '_' or '.'.
        InvalidFlag,
        /// Flags come before operands, so `--` can separate them.
        FlagAfterOperand,
        /// The program does not accept `--`, so an operand starting with '-' could be
        /// read as an option.
        OperandLooksLikeOption,
        CommandTooLong { max_bytes: u64 },
        StdinTooLong { max_bytes: u64 },
        StdinAlreadySet,
        /// The secret appears in the encoded command; secrets go over stdin only.
        SecretInArgv,
        /// A replacement password is at least the minimum length, and has no NUL, CR or
        /// LF, since stdin carries it as one line.
        UnsuitableSecret,
        Management { refusal: ManagementRefusal },
    }
}

impl fmt::Display for ArgvRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgram => f.write_str(
                "a remote program is an absolute path of letters, digits, '.', '_', '+', '-' \
                 and '/'",
            ),
            Self::NulInArgument => f.write_str("an argument cannot contain NUL"),
            Self::ArgumentTooLong { max_bytes } => {
                write!(f, "an argument is longer than {max_bytes} bytes")
            }
            Self::InvalidFlag => f.write_str("a flag is '-' or '--' followed by a fixed name"),
            Self::FlagAfterOperand => f.write_str("flags come before operands"),
            Self::OperandLooksLikeOption => {
                f.write_str("the program does not accept '--', so an operand cannot start with '-'")
            }
            Self::CommandTooLong { max_bytes } => {
                write!(f, "the encoded command is longer than {max_bytes} bytes")
            }
            Self::StdinTooLong { max_bytes } => write!(f, "stdin is longer than {max_bytes} bytes"),
            Self::StdinAlreadySet => f.write_str("this invocation already has its stdin payload"),
            Self::SecretInArgv => f.write_str(
                "the secret appears in the command arguments; secrets go over stdin only",
            ),
            Self::UnsuitableSecret => {
                f.write_str("the replacement password is too short or contains NUL, CR or LF")
            }
            Self::Management { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ArgvRefusal {}

impl From<ManagementRefusal> for ArgvRefusal {
    fn from(refusal: ManagementRefusal) -> Self {
        Self::Management { refusal }
    }
}

fn max_bytes(limit: usize) -> u64 {
    u64::try_from(limit).unwrap_or(u64::MAX)
}

/// An absolute program path on the remote host.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ProgramPath(String);

impl ProgramPath {
    /// Accepts an absolute path of letters, digits, '.', '_', '+', '-' and '/' without
    /// empty, '.' or '..' components.
    pub fn new(path: impl Into<String>) -> Result<Self, ArgvRefusal> {
        let path = path.into();
        let Some(rest) = path.strip_prefix('/') else {
            return Err(ArgvRefusal::InvalidProgram);
        };
        let characters_ok = path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-' | b'/')
        });
        let components_ok = rest
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));
        if !characters_ok || !components_ok || path.len() > MAX_PROGRAM_PATH_BYTES {
            return Err(ArgvRefusal::InvalidProgram);
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One operand: any text without NUL, passed as exactly one argument.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RemoteArg(String);

impl RemoteArg {
    /// Accepts any text without NUL, up to [`MAX_REMOTE_ARG_BYTES`].
    pub fn new(value: impl Into<String>) -> Result<Self, ArgvRefusal> {
        let value = value.into();
        if value.contains('\0') {
            return Err(ArgvRefusal::NulInArgument);
        }
        if value.len() > MAX_REMOTE_ARG_BYTES {
            return Err(ArgvRefusal::ArgumentTooLong {
                max_bytes: max_bytes(MAX_REMOTE_ARG_BYTES),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether the program treats `--` as the end of its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionTerminator {
    DoubleDash,
    NotSupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Word {
    Flag(&'static str),
    FlagValue {
        flag: &'static str,
        value: RemoteArg,
    },
    Operand(RemoteArg),
}

/// A remote command as typed argv. See the module notes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemoteCommand {
    program: ProgramPath,
    terminator: OptionTerminator,
    words: Vec<Word>,
}

fn check_flag(flag: &str) -> Result<(), ArgvRefusal> {
    let name = flag
        .strip_prefix("--")
        .or_else(|| flag.strip_prefix('-'))
        .ok_or(ArgvRefusal::InvalidFlag)?;
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let rest_ok = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(ArgvRefusal::InvalidFlag)
    }
}

impl RemoteCommand {
    /// A command running `program`, which does or does not accept `--`.
    pub fn new(program: ProgramPath, terminator: OptionTerminator) -> Self {
        Self {
            program,
            terminator,
            words: Vec::new(),
        }
    }

    fn has_operand(&self) -> bool {
        self.words
            .iter()
            .any(|word| matches!(word, Word::Operand(_)))
    }

    /// Adds a fixed flag such as `-v` or `--verbose`.
    pub fn flag(mut self, flag: &'static str) -> Result<Self, ArgvRefusal> {
        check_flag(flag)?;
        if self.has_operand() {
            return Err(ArgvRefusal::FlagAfterOperand);
        }
        self.words.push(Word::Flag(flag));
        Ok(self)
    }

    /// Adds `--flag=value` as one argument; `value` may be any text without NUL.
    pub fn flag_value(
        mut self,
        flag: &'static str,
        value: impl Into<String>,
    ) -> Result<Self, ArgvRefusal> {
        if !flag.starts_with("--") {
            return Err(ArgvRefusal::InvalidFlag);
        }
        check_flag(flag)?;
        if self.has_operand() {
            return Err(ArgvRefusal::FlagAfterOperand);
        }
        let value = RemoteArg::new(value)?;
        self.words.push(Word::FlagValue { flag, value });
        Ok(self)
    }

    /// Adds an operand, passed as exactly one argument.
    pub fn operand(mut self, value: impl Into<String>) -> Result<Self, ArgvRefusal> {
        let value = RemoteArg::new(value)?;
        if value.as_str().starts_with('-') && self.terminator == OptionTerminator::NotSupported {
            return Err(ArgvRefusal::OperandLooksLikeOption);
        }
        self.words.push(Word::Operand(value));
        Ok(self)
    }

    pub fn program(&self) -> &ProgramPath {
        &self.program
    }

    /// The arguments the remote program receives, program first, with `--` before the
    /// first operand when the program accepts it.
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec![self.program.as_str().to_owned()];
        let mut terminated = false;
        for word in &self.words {
            match word {
                Word::Flag(flag) => argv.push((*flag).to_owned()),
                Word::FlagValue { flag, value } => argv.push(format!("{flag}={}", value.as_str())),
                Word::Operand(value) => {
                    if !terminated && self.terminator == OptionTerminator::DoubleDash {
                        argv.push("--".to_owned());
                        terminated = true;
                    }
                    argv.push(value.as_str().to_owned());
                }
            }
        }
        argv
    }
}

/// Shell text produced by [`encode_posix`]; it cannot be made from a string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EncodedCommand(String);

impl EncodedCommand {
    /// The text the SSH transport hands to the remote POSIX shell.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EncodedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncodedCommand({:?})", self.0)
    }
}

/// The one encoder: every argument becomes one single-quoted word, each `'` inside it
/// written as `'\''`, and the words are joined by single spaces. A POSIX shell reads the
/// result back as exactly [`RemoteCommand::argv`], with no expansion, operator or
/// comment.
pub fn encode_posix(command: &RemoteCommand) -> Result<EncodedCommand, ArgvRefusal> {
    let mut encoded = String::new();
    for (index, word) in command.argv().iter().enumerate() {
        if index > 0 {
            encoded.push(' ');
        }
        encoded.push('\'');
        for character in word.chars() {
            if character == '\'' {
                encoded.push_str("'\\''");
            } else {
                encoded.push(character);
            }
        }
        encoded.push('\'');
        if encoded.len() > MAX_ENCODED_COMMAND_BYTES {
            return Err(ArgvRefusal::CommandTooLong {
                max_bytes: max_bytes(MAX_ENCODED_COMMAND_BYTES),
            });
        }
    }
    Ok(EncodedCommand(encoded))
}

/// A secret bound for the remote side. It is never serialized, has no `Display` and no
/// conversion to text or to an operand, and its `Debug` output is redacted.
pub struct RemoteSecret(Vec<u8>);

impl RemoteSecret {
    /// Wraps secret bytes; they leave only through a typed stdin operation.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The length, which is not secret.
    pub fn len_bytes(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for RemoteSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteSecret(redacted)")
    }
}

/// Bytes for the remote command's stdin. Never serialized; `Debug` shows the length only.
pub struct StdinPayload(Vec<u8>);

impl StdinPayload {
    /// The bytes, for the SSH transport that writes them to the channel's stdin.
    pub fn expose_to_transport(&self) -> &[u8] {
        &self.0
    }

    pub fn len_bytes(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for StdinPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StdinPayload({} bytes, redacted)", self.0.len())
    }
}

/// One management command ready for the SSH transport: the action it performs, where it
/// runs, its encoded argv and any stdin. It has no `Serialize`, so its stdin is never
/// written into a record.
#[derive(Debug)]
pub struct RemoteInvocation {
    action: ManagementAction,
    context: ExecutionContext,
    command: EncodedCommand,
    stdin: Option<StdinPayload>,
}

impl RemoteInvocation {
    pub fn action(&self) -> ManagementAction {
        self.action
    }

    pub fn context(&self) -> ExecutionContext {
        self.context
    }

    pub fn command(&self) -> &EncodedCommand {
        &self.command
    }

    pub fn stdin(&self) -> Option<&StdinPayload> {
        self.stdin.as_ref()
    }

    /// Attach a bounded request once. Payload bytes have no conversion to argv,
    /// are omitted from Debug, and are sent only by the authenticated SSH port.
    pub fn with_stdin(mut self, input: RemoteSecret) -> Result<Self, ArgvRefusal> {
        if self.stdin.is_some() {
            return Err(ArgvRefusal::StdinAlreadySet);
        }
        if input.0.len() > MAX_REMOTE_STDIN_BYTES {
            return Err(ArgvRefusal::StdinTooLong {
                max_bytes: max_bytes(MAX_REMOTE_STDIN_BYTES),
            });
        }
        if !input.0.is_empty() && find_encoded(self.command.as_str().as_bytes(), &input.0).is_some()
        {
            return Err(ArgvRefusal::SecretInArgv);
        }
        self.stdin = Some(StdinPayload(input.0));
        Ok(self)
    }

    /// Builds an invocation of `command` for `action` in `context`, under a current
    /// management identity that permits the action on that host.
    pub fn new(
        identity: &ManagementIdentity,
        known: &KnownHosts,
        action: ManagementAction,
        context: ExecutionContext,
        command: &RemoteCommand,
    ) -> Result<Self, ArgvRefusal> {
        identity.check_current(known)?;
        identity.permits(action)?;
        if context.host() != identity.host() {
            return Err(ManagementRefusal::WrongHost {
                identity: identity.host(),
                context: context.host(),
            }
            .into());
        }
        if !runs_in(action, context) {
            return Err(ManagementRefusal::WrongContext { action }.into());
        }
        Ok(Self {
            action,
            context,
            command: encode_posix(command)?,
            stdin: None,
        })
    }
}

/// Where each management action runs: VM lifecycle on the host shell, the Jupyter
/// password where Jupyter runs, logs anywhere.
fn runs_in(action: ManagementAction, context: ExecutionContext) -> bool {
    match action {
        ManagementAction::LaunchVm
        | ManagementAction::SuperviseVm
        | ManagementAction::TerminateVm => {
            matches!(context, ExecutionContext::RemoteHostShell { .. })
        }
        ManagementAction::ReplaceJupyterPassword => matches!(
            context,
            ExecutionContext::ProviderContainer { .. } | ExecutionContext::VmWorkload { .. }
        ),
        ManagementAction::CollectLogs => true,
    }
}

/// VM-D14: replaces the bootstrap Jupyter password after the pod or VM runs. The helper
/// is called as `<helper> --replace-jupyter-password --password-from-stdin`, and the new
/// password goes over stdin as one line, never in argv (§4.5). The encoded command is
/// checked for the password before it is returned.
pub fn replace_jupyter_password(
    identity: &ManagementIdentity,
    known: &KnownHosts,
    context: ExecutionContext,
    helper: &ProgramPath,
    new_password: RemoteSecret,
) -> Result<RemoteInvocation, ArgvRefusal> {
    let secret = new_password.0;
    if secret.len() < MIN_JUPYTER_PASSWORD_BYTES
        || secret
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(ArgvRefusal::UnsuitableSecret);
    }
    let command = RemoteCommand::new(helper.clone(), OptionTerminator::DoubleDash)
        .flag("--replace-jupyter-password")?
        .flag("--password-from-stdin")?;
    let mut invocation = RemoteInvocation::new(
        identity,
        known,
        ManagementAction::ReplaceJupyterPassword,
        context,
        &command,
    )?;
    if find_encoded(invocation.command.as_str().as_bytes(), &secret).is_some() {
        return Err(ArgvRefusal::SecretInArgv);
    }
    let mut stdin = secret;
    stdin.push(b'\n');
    invocation.stdin = Some(StdinPayload(stdin));
    Ok(invocation)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::foundation::ids::MonotonicTime;
    use crate::sandbox_contract::remote::fakes::{host_id, host_key, mgmt_key, vm_id, SeededRng};
    use crate::sandbox_contract::remote::ssh::{
        EnrollmentEvidence, EnrollmentPolicy, RemoteAccountName, RemoteShellKind,
    };

    /// Why the reference tokenizer did not read a command as plain literal words.
    #[derive(Debug, PartialEq, Eq)]
    enum NotLiteral {
        Operator(char),
        Expansion(char),
        Glob(char),
        Comment,
        Tilde,
        Brace,
        Unterminated,
    }

    /// A reference POSIX shell tokenizer (XCU 2.2–2.3), written independently of the
    /// encoder. It returns the words a shell would pass to the program, and refuses any
    /// input in which an unquoted character would be an operator, an expansion, a glob,
    /// a comment, a tilde or a brace expansion, or in which a quote is left open.
    fn tokenize(input: &str) -> Result<Vec<String>, NotLiteral> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut in_word = false;
        let mut characters = input.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                ' ' | '\t' => {
                    if in_word {
                        words.push(std::mem::take(&mut word));
                        in_word = false;
                    }
                }
                '\'' => {
                    in_word = true;
                    loop {
                        match characters.next() {
                            Some('\'') => break,
                            Some(inner) => word.push(inner),
                            None => return Err(NotLiteral::Unterminated),
                        }
                    }
                }
                '"' => {
                    in_word = true;
                    loop {
                        match characters.next() {
                            Some('"') => break,
                            Some('\\') => match characters.next() {
                                Some(escaped @ ('$' | '`' | '"' | '\\')) => word.push(escaped),
                                Some('\n') => {}
                                Some(other) => {
                                    word.push('\\');
                                    word.push(other);
                                }
                                None => return Err(NotLiteral::Unterminated),
                            },
                            Some(expansion @ ('$' | '`')) => {
                                return Err(NotLiteral::Expansion(expansion))
                            }
                            Some(inner) => word.push(inner),
                            None => return Err(NotLiteral::Unterminated),
                        }
                    }
                }
                '\\' => match characters.next() {
                    Some('\n') => {}
                    Some(escaped) => {
                        in_word = true;
                        word.push(escaped);
                    }
                    None => return Err(NotLiteral::Unterminated),
                },
                ';' | '&' | '|' | '(' | ')' | '<' | '>' | '\n' => {
                    return Err(NotLiteral::Operator(character))
                }
                '$' | '`' => return Err(NotLiteral::Expansion(character)),
                '*' | '?' | '[' => return Err(NotLiteral::Glob(character)),
                '#' if !in_word => return Err(NotLiteral::Comment),
                '~' if !in_word => return Err(NotLiteral::Tilde),
                '{' | '}' => return Err(NotLiteral::Brace),
                other => {
                    in_word = true;
                    word.push(other);
                }
            }
        }
        if in_word {
            words.push(word);
        }
        Ok(words)
    }

    fn program() -> ProgramPath {
        ProgramPath::new("/usr/bin/printf").unwrap()
    }

    fn hostile() -> Vec<&'static str> {
        vec![
            "; rm -rf /",
            "a && b",
            "a || b",
            "a | b",
            "$(id)",
            "${HOME}",
            "$HOME",
            "`id`",
            "line one\nline two",
            "carriage\rreturn",
            "*",
            "/etc/*.conf",
            "file?",
            "[abc]",
            "it's",
            "'",
            "''",
            "\"double\"",
            "\\",
            "back\\slash",
            "-rf",
            "--force",
            "-",
            "",
            " ",
            "\t",
            "#comment",
            "~root",
            "{a,b}",
            "a > /tmp/x",
            "< /etc/passwd",
            "&",
            "!!",
            "a=b",
            "ünïcödé ✓",
            "'; echo pwned; '",
        ]
    }

    #[test]
    fn hostile_operands_stay_single_literal_arguments() {
        let mut command = RemoteCommand::new(program(), OptionTerminator::DoubleDash);
        for operand in hostile() {
            command = command.operand(operand).unwrap();
        }
        let encoded = encode_posix(&command).unwrap();
        let argv = command.argv();
        assert_eq!(tokenize(encoded.as_str()), Ok(argv.clone()));
        assert_eq!(argv[0], "/usr/bin/printf");
        assert_eq!(argv[1], "--");
        assert_eq!(&argv[2..], hostile().as_slice());
    }

    #[test]
    fn each_hostile_operand_alone_is_one_literal_word() {
        for operand in hostile() {
            let command = RemoteCommand::new(program(), OptionTerminator::DoubleDash)
                .operand(operand)
                .unwrap();
            let words = tokenize(encode_posix(&command).unwrap().as_str()).unwrap();
            assert_eq!(words, vec!["/usr/bin/printf", "--", operand], "{operand:?}");
        }
    }

    #[test]
    fn the_reference_tokenizer_catches_what_unquoted_text_would_do() {
        assert_eq!(tokenize("a; b"), Err(NotLiteral::Operator(';')));
        assert_eq!(tokenize("a && b"), Err(NotLiteral::Operator('&')));
        assert_eq!(tokenize("a | b"), Err(NotLiteral::Operator('|')));
        assert_eq!(tokenize("$(id)"), Err(NotLiteral::Expansion('$')));
        assert_eq!(tokenize("`id`"), Err(NotLiteral::Expansion('`')));
        assert_eq!(tokenize("\"$(id)\""), Err(NotLiteral::Expansion('$')));
        assert_eq!(tokenize("a\nb"), Err(NotLiteral::Operator('\n')));
        assert_eq!(tokenize("*.txt"), Err(NotLiteral::Glob('*')));
        assert_eq!(tokenize("#x"), Err(NotLiteral::Comment));
        assert_eq!(tokenize("~"), Err(NotLiteral::Tilde));
        assert_eq!(tokenize("{a,b}"), Err(NotLiteral::Brace));
        assert_eq!(tokenize("'open"), Err(NotLiteral::Unterminated));
        assert_eq!(tokenize("a b"), Ok(vec!["a".to_owned(), "b".to_owned()]));
        assert_eq!(tokenize("'a b'"), Ok(vec!["a b".to_owned()]));
        assert_eq!(tokenize("''"), Ok(vec![String::new()]));
        assert_eq!(tokenize("'it'\\''s'"), Ok(vec!["it's".to_owned()]));
    }

    #[test]
    fn random_operands_round_trip_as_single_words() {
        const ALPHABET: &[char] = &[
            'a', 'Z', '0', ' ', '\t', '\n', '\r', ';', '&', '|', '$', '(', ')', '`', '\'', '"',
            '\\', '*', '?', '[', ']', '{', '}', '~', '#', '-', '=', '<', '>', '!', '%', 'é', '✓',
        ];
        let mut rng = SeededRng::new(0x5eed_a12c);
        for _ in 0..2_000 {
            let count = rng.below(5);
            let mut command = RemoteCommand::new(program(), OptionTerminator::DoubleDash);
            let mut operands = Vec::new();
            for _ in 0..count {
                let length = rng.below(12);
                let operand: String = (0..length)
                    .map(|_| ALPHABET[usize::try_from(rng.below(ALPHABET.len() as u64)).unwrap()])
                    .collect();
                command = command.operand(operand.clone()).unwrap();
                operands.push(operand);
            }
            let words = tokenize(encode_posix(&command).unwrap().as_str()).unwrap();
            assert_eq!(words, command.argv());
            let first_operand = if operands.is_empty() { 1 } else { 2 };
            assert_eq!(&words[first_operand..], operands.as_slice());
        }
    }

    #[test]
    fn flags_are_fixed_text_and_come_first() {
        let command = RemoteCommand::new(program(), OptionTerminator::DoubleDash)
            .flag("-v")
            .unwrap()
            .flag_value("--name", "x; rm -rf / $(id)")
            .unwrap()
            .operand("-rf")
            .unwrap();
        let words = tokenize(encode_posix(&command).unwrap().as_str()).unwrap();
        assert_eq!(
            words,
            vec![
                "/usr/bin/printf",
                "-v",
                "--name=x; rm -rf / $(id)",
                "--",
                "-rf"
            ]
        );
        assert_eq!(
            RemoteCommand::new(program(), OptionTerminator::DoubleDash)
                .operand("x")
                .unwrap()
                .flag("-v"),
            Err(ArgvRefusal::FlagAfterOperand)
        );
        for bad in ["", "-", "--", "v", "-v;", "-$x", "--a b", "---x", "-v=1"] {
            assert_eq!(
                RemoteCommand::new(program(), OptionTerminator::DoubleDash).flag(bad),
                Err(ArgvRefusal::InvalidFlag),
                "{bad:?}"
            );
        }
        assert_eq!(
            RemoteCommand::new(program(), OptionTerminator::DoubleDash).flag_value("-n", "1"),
            Err(ArgvRefusal::InvalidFlag)
        );
    }

    #[test]
    fn a_program_without_double_dash_refuses_dash_operands() {
        let command = RemoteCommand::new(program(), OptionTerminator::NotSupported);
        assert_eq!(
            command.clone().operand("-rf"),
            Err(ArgvRefusal::OperandLooksLikeOption)
        );
        let command = command.operand("plain").unwrap();
        assert_eq!(command.argv(), vec!["/usr/bin/printf", "plain"]);
    }

    #[test]
    fn nul_and_bad_programs_are_refused() {
        assert_eq!(RemoteArg::new("a\0b"), Err(ArgvRefusal::NulInArgument));
        assert!(matches!(
            RemoteArg::new("x".repeat(MAX_REMOTE_ARG_BYTES + 1)),
            Err(ArgvRefusal::ArgumentTooLong { .. })
        ));
        for bad in [
            "",
            "printf",
            "./printf",
            "/usr/../bin/sh",
            "/usr//bin",
            "/usr/bin/",
            "/usr/bin/a b",
            "/usr/bin/$(id)",
            "/usr/bin/a;b",
        ] {
            assert_eq!(
                ProgramPath::new(bad),
                Err(ArgvRefusal::InvalidProgram),
                "{bad:?}"
            );
        }
        assert!(ProgramPath::new("/opt/yougori/bin/yougori-remote").is_ok());
    }

    #[test]
    fn an_overlong_command_is_refused() {
        let mut command = RemoteCommand::new(program(), OptionTerminator::DoubleDash);
        for _ in 0..9 {
            command = command.operand("'".repeat(40_000)).unwrap();
        }
        assert!(matches!(
            encode_posix(&command),
            Err(ArgvRefusal::CommandTooLong { .. })
        ));
    }

    fn identity_for(actions: &[ManagementAction]) -> (KnownHosts, ManagementIdentity) {
        let mut known = KnownHosts::new();
        let enrollment = known
            .enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(1).fingerprint(),
                },
                EnrollmentPolicy::default(),
                MonotonicTime::ZERO,
            )
            .unwrap();
        let identity = ManagementIdentity::new(
            &enrollment,
            RemoteAccountName::new("yougori").unwrap(),
            mgmt_key(),
            RemoteShellKind::Posix,
            actions.iter().copied().collect::<BTreeSet<_>>(),
        )
        .unwrap();
        (known, identity)
    }

    fn helper() -> ProgramPath {
        ProgramPath::new("/opt/yougori/bin/yougori-remote").unwrap()
    }

    fn pod() -> ExecutionContext {
        ExecutionContext::ProviderContainer { host: host_id(1) }
    }

    const PASSWORD: &[u8] = b"correct-horse-battery-staple-42";

    #[test]
    fn management_input_is_bounded_redacted_and_cannot_replace_an_existing_payload() {
        let (known, identity) = identity_for(&[ManagementAction::LaunchVm]);
        let command = RemoteCommand::new(helper(), OptionTerminator::NotSupported);
        let invocation = || {
            RemoteInvocation::new(
                &identity,
                &known,
                ManagementAction::LaunchVm,
                ExecutionContext::RemoteHostShell {
                    host: identity.host(),
                },
                &command,
            )
            .unwrap()
        };
        let request = invocation()
            .with_stdin(RemoteSecret::new(PASSWORD.to_vec()))
            .unwrap();
        assert_eq!(request.stdin().unwrap().expose_to_transport(), PASSWORD);
        assert!(!format!("{request:?}").contains("correct-horse"));
        assert!(!request.command().as_str().contains("correct-horse"));
        assert!(matches!(
            request.with_stdin(RemoteSecret::new(Vec::new())),
            Err(ArgvRefusal::StdinAlreadySet)
        ));
        assert!(matches!(
            invocation().with_stdin(RemoteSecret::new(vec![0; MAX_REMOTE_STDIN_BYTES + 1])),
            Err(ArgvRefusal::StdinTooLong { .. })
        ));
        assert!(matches!(
            invocation().with_stdin(RemoteSecret::new(helper().as_str().as_bytes().to_vec())),
            Err(ArgvRefusal::SecretInArgv)
        ));
    }

    #[test]
    fn the_jupyter_password_goes_over_stdin_and_never_into_argv() {
        let (known, identity) = identity_for(&[ManagementAction::ReplaceJupyterPassword]);
        let invocation = replace_jupyter_password(
            &identity,
            &known,
            pod(),
            &helper(),
            RemoteSecret::new(PASSWORD.to_vec()),
        )
        .unwrap();
        let command = invocation.command().as_str();
        assert_eq!(
            tokenize(command).unwrap(),
            vec![
                "/opt/yougori/bin/yougori-remote",
                "--replace-jupyter-password",
                "--password-from-stdin"
            ]
        );
        assert!(find_encoded(command.as_bytes(), PASSWORD).is_none());
        let mut line = PASSWORD.to_vec();
        line.push(b'\n');
        assert_eq!(
            invocation.stdin().unwrap().expose_to_transport(),
            line.as_slice()
        );
        assert_eq!(
            invocation.action(),
            ManagementAction::ReplaceJupyterPassword
        );
        let debug = format!("{invocation:?}");
        assert!(!debug.contains("correct-horse"), "{debug}");
        assert!(debug.contains("redacted"));
        assert_eq!(
            format!("{:?}", RemoteSecret::new(PASSWORD.to_vec())),
            "RemoteSecret(redacted)"
        );
        // It also runs inside a VM workload.
        let vm = ExecutionContext::VmWorkload {
            host: host_id(1),
            vm: vm_id(1),
        };
        assert!(replace_jupyter_password(
            &identity,
            &known,
            vm,
            &helper(),
            RemoteSecret::new(PASSWORD.to_vec())
        )
        .is_ok());
    }

    #[test]
    fn a_secret_that_would_appear_in_argv_is_refused() {
        let (known, identity) = identity_for(&[ManagementAction::ReplaceJupyterPassword]);
        let leaky = ProgramPath::new("/opt/correct-horse-battery-staple-42/bin/helper").unwrap();
        assert_eq!(
            replace_jupyter_password(
                &identity,
                &known,
                pod(),
                &leaky,
                RemoteSecret::new(PASSWORD.to_vec())
            )
            .map(|_| ()),
            Err(ArgvRefusal::SecretInArgv)
        );
    }

    #[test]
    fn unsuitable_passwords_and_missing_permissions_are_refused() {
        let (known, identity) = identity_for(&[ManagementAction::ReplaceJupyterPassword]);
        for bad in [
            &b"short"[..],
            b"sixteen-bytes-ok\nx",
            b"sixteen-bytes-ok\0x",
            b"sixteen-bytes-ok\rx",
        ] {
            assert_eq!(
                replace_jupyter_password(
                    &identity,
                    &known,
                    pod(),
                    &helper(),
                    RemoteSecret::new(bad.to_vec())
                )
                .map(|_| ()),
                Err(ArgvRefusal::UnsuitableSecret)
            );
        }
        let (known, identity) = identity_for(&[ManagementAction::LaunchVm]);
        assert_eq!(
            replace_jupyter_password(
                &identity,
                &known,
                pod(),
                &helper(),
                RemoteSecret::new(PASSWORD.to_vec())
            )
            .map(|_| ()),
            Err(ArgvRefusal::Management {
                refusal: ManagementRefusal::ActionNotPermitted {
                    action: ManagementAction::ReplaceJupyterPassword
                }
            })
        );
    }

    #[test]
    fn invocations_check_host_context_and_current_enrollment() {
        let (mut known, identity) =
            identity_for(&[ManagementAction::LaunchVm, ManagementAction::CollectLogs]);
        let command = RemoteCommand::new(helper(), OptionTerminator::DoubleDash)
            .flag("--launch-vm")
            .unwrap();
        let shell = ExecutionContext::RemoteHostShell { host: host_id(1) };
        assert!(RemoteInvocation::new(
            &identity,
            &known,
            ManagementAction::LaunchVm,
            shell,
            &command
        )
        .is_ok());
        assert_eq!(
            RemoteInvocation::new(
                &identity,
                &known,
                ManagementAction::LaunchVm,
                pod(),
                &command
            )
            .map(|_| ()),
            Err(ArgvRefusal::Management {
                refusal: ManagementRefusal::WrongContext {
                    action: ManagementAction::LaunchVm
                }
            })
        );
        let elsewhere = ExecutionContext::RemoteHostShell { host: host_id(2) };
        assert!(matches!(
            RemoteInvocation::new(
                &identity,
                &known,
                ManagementAction::CollectLogs,
                elsewhere,
                &command
            ),
            Err(ArgvRefusal::Management {
                refusal: ManagementRefusal::WrongHost { .. }
            })
        ));
        known.retire(&host_id(1));
        assert!(matches!(
            RemoteInvocation::new(
                &identity,
                &known,
                ManagementAction::LaunchVm,
                shell,
                &command
            ),
            Err(ArgvRefusal::Management {
                refusal: ManagementRefusal::StaleEnrollment { .. }
            })
        ));
    }
}
