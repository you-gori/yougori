//! The terminal while the screen runs: raw mode, the alternate screen, bracketed paste, the
//! cursor; all put back on exit, on error and on a panic. No mouse capture, so the person can
//! still select and copy text.
//!
//! Frames are written by a thread of their own ([`Output`]): a terminal that stops reading (the
//! launcher's relay paused, the VM's guest gave up on it) then never blocks the screen's loop, so
//! keys, engine events and termination signals are still handled, and quitting is never held up
//! by output that cannot be written.
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static KEYBOARD: AtomicBool = AtomicBool::new(false);
/// Panics on other threads while the screen runs: shown on the screen, not printed over it.
static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// The writer thread's queue, so putting the terminal back (also from the panic hook) goes after
/// the frames already queued instead of through them.
static WRITER: Mutex<Option<mpsc::Sender<Chunk>>> = Mutex::new(None);
type Hook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;
static PREVIOUS: Mutex<Option<Hook>> = Mutex::new(None);

/// How long putting the terminal back waits for output that is still being written.
const RESTORE_WAIT: Duration = Duration::from_secs(2);

/// What the writer thread writes, in order.
enum Chunk {
    Frame(Vec<u8>),
    /// The last bytes (putting the terminal back); the sender hears once they are written.
    Last(Vec<u8>, mpsc::Sender<()>),
}

/// Writes to the terminal on a thread of its own and tells when each frame was written.
pub struct Output {
    chunks: mpsc::Sender<Chunk>,
    done: tokio::sync::mpsc::UnboundedReceiver<io::Result<()>>,
    /// Frames handed over and not yet written.
    writing: usize,
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the terminal can no longer be written to")
}

impl Output {
    /// Starts the thread that writes to `out`. It ends after the last bytes, when a write
    /// fails, or when the output is dropped.
    pub fn start(mut out: Box<dyn Write + Send>) -> io::Result<Output> {
        let (chunks, queue) = mpsc::channel::<Chunk>();
        let (written, done) = tokio::sync::mpsc::unbounded_channel();
        std::thread::Builder::new().name("yougori-screen-write".into()).spawn(move || {
            for chunk in queue {
                match chunk {
                    Chunk::Frame(bytes) => {
                        let result = out.write_all(&bytes).and_then(|_| out.flush());
                        let failed = result.is_err();
                        let _ = written.send(result);
                        if failed {
                            return;
                        }
                    }
                    Chunk::Last(bytes, heard) => {
                        if out.write_all(&bytes).and_then(|_| out.flush()).is_ok() {
                            let _ = heard.send(());
                        }
                        return;
                    }
                }
            }
        })?;
        Ok(Output { chunks, done, writing: 0 })
    }

    /// Hands a frame to the writer; it is written in the background. An error means the
    /// terminal can no longer be written to (an earlier write failed).
    pub fn write(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.chunks.send(Chunk::Frame(bytes)).map_err(|_| stopped())?;
        self.writing += 1;
        Ok(())
    }

    /// Whether a frame is still being written. The next frame waits for it, so frames never pile
    /// up behind a terminal that reads slowly: the next one then carries every change since.
    pub fn writing(&self) -> bool {
        self.writing > 0
    }

    /// How the next frame handed over was written; waits for ever while none is being written.
    pub async fn written(&mut self) -> io::Result<()> {
        if self.writing == 0 {
            return std::future::pending().await;
        }
        let result = self.done.recv().await.unwrap_or_else(|| Err(stopped()));
        self.writing -= 1;
        result
    }

    /// Writes `bytes` after everything queued, then ends the thread; false when they were not
    /// written within `wait` (the terminal stopped reading) or cannot be written at all.
    fn finish(chunks: &mpsc::Sender<Chunk>, bytes: Vec<u8>, wait: Duration) -> bool {
        let (heard, written) = mpsc::channel();
        chunks.send(Chunk::Last(bytes, heard)).is_ok() && written.recv_timeout(wait).is_ok()
    }
}

pub struct Terminal {
    output: Output,
}

impl Terminal {
    /// Takes over the terminal. Panics on this thread put it back before their message prints.
    pub fn enter() -> io::Result<Terminal> {
        #[cfg(windows)]
        let _ = crossterm::ansi_support::supports_ansi();
        crossterm::terminal::enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        install_hook(std::thread::current().id());
        // Alternate screen; the wheel does not turn into arrow keys (that would page through
        // the prompt history); cursor hidden until a frame places it; screen cleared.
        // Bracketed paste only where pastes arrive as terminal input (on Windows they come as keys).
        let setup = if cfg!(unix) {
            "\x1b[?1049h\x1b[?1007l\x1b[?25l\x1b[0m\x1b[2J\x1b[H\x1b[?2004h"
        } else {
            "\x1b[?1049h\x1b[?1007l\x1b[?25l\x1b[0m\x1b[2J\x1b[H"
        };
        let mut out = io::stdout().lock();
        let started = out
            .write_all(setup.as_bytes())
            .and_then(|_| out.flush())
            .and_then(|_| Output::start(Box::new(io::stdout())));
        drop(out);
        match started {
            Ok(output) => {
                if let Ok(mut writer) = WRITER.lock() {
                    *writer = Some(output.chunks.clone());
                }
                Ok(Terminal { output })
            }
            Err(error) => {
                restore();
                uninstall_hook();
                Err(error)
            }
        }
    }

    /// Columns and rows.
    pub fn size() -> (u16, u16) {
        crossterm::terminal::size().ok().filter(|(w, h)| *w > 0 && *h > 0).unwrap_or((100, 30))
    }

    /// Hands a frame to the writer thread (see [`Output::write`]).
    pub fn write(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        self.output.write(bytes)
    }

    /// Whether a frame is still being written (see [`Output::writing`]).
    pub fn writing(&self) -> bool {
        self.output.writing()
    }

    /// How the frame being written went (see [`Output::written`]).
    pub async fn written(&mut self) -> io::Result<()> {
        self.output.written().await
    }

    /// Asks the terminal to report Shift+Enter apart from Enter (the keyboard protocol's
    /// first level), when it says it can. Waits up to two seconds for its answer.
    pub fn enhance_keyboard() -> bool {
        #[cfg(unix)]
        {
            if matches!(crossterm::terminal::supports_keyboard_enhancement(), Ok(true)) && ACTIVE.load(Ordering::SeqCst)
            {
                let mut out = io::stdout().lock();
                if out.write_all(b"\x1b[>1u").and_then(|_| out.flush()).is_ok() {
                    KEYBOARD.store(true, Ordering::SeqCst);
                    return true;
                }
            }
        }
        false
    }

    /// Panic messages from other threads since the last call.
    pub fn panics() -> Vec<String> {
        PANICS.lock().map(|mut p| std::mem::take(&mut *p)).unwrap_or_default()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        restore();
        // The panic hook cannot be changed while this thread unwinds from a panic.
        if !std::thread::panicking() {
            uninstall_hook();
        }
    }
}

/// Puts the terminal back as it was (once). The sequence goes after the frames already queued;
/// when the terminal does not take it within [`RESTORE_WAIT`] it is given up, so a terminal that
/// stopped reading never keeps the process from ending.
pub fn restore() {
    if !ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut sequence = String::new();
    if KEYBOARD.swap(false, Ordering::SeqCst) {
        sequence.push_str("\x1b[<u");
    }
    sequence.push_str("\x1b[0m\x1b[?2026l\x1b[?2004l\x1b[?1007h\x1b[?25h\x1b[?1049l");
    let writer = WRITER.lock().ok().and_then(|mut writer| writer.take());
    match writer {
        Some(chunks) => {
            Output::finish(&chunks, sequence.into_bytes(), RESTORE_WAIT);
        }
        None => {
            let mut out = io::stdout();
            let _ = out.write_all(sequence.as_bytes());
            let _ = out.flush();
        }
    }
    let _ = crossterm::terminal::disable_raw_mode();
}

fn install_hook(screen: ThreadId) {
    let previous = std::panic::take_hook();
    if let Ok(mut slot) = PREVIOUS.lock() {
        *slot = Some(previous);
    }
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == screen || !ACTIVE.load(Ordering::SeqCst) {
            restore();
            if let Ok(slot) = PREVIOUS.lock() {
                if let Some(previous) = slot.as_ref() {
                    previous(info);
                    return;
                }
            }
            eprintln!("{info}");
        } else if let Ok(mut panics) = PANICS.lock() {
            panics.push(info.to_string());
        }
    }));
}

fn uninstall_hook() {
    let previous = PREVIOUS.lock().ok().and_then(|mut slot| slot.take());
    if let Some(previous) = previous {
        std::panic::set_hook(previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar};
    use std::time::Instant;

    /// Whether the gate is open, the bytes it took, and the signal that it opened.
    type GateState = Arc<(Mutex<(bool, Vec<u8>)>, Condvar)>;

    /// A terminal that takes bytes only while it is open, like a relay that stopped polling.
    #[derive(Clone, Default)]
    struct Gate {
        state: GateState,
    }

    impl Gate {
        fn open(&self) {
            let (lock, ready) = &*self.state;
            lock.lock().unwrap().0 = true;
            ready.notify_all();
        }

        fn taken(&self) -> Vec<u8> {
            self.state.0.lock().unwrap().1.clone()
        }
    }

    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.state;
            let mut state = ready.wait_while(lock.lock().unwrap(), |s| !s.0).unwrap();
            state.1.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_terminal_that_stops_reading_never_blocks_the_screen_or_its_end() {
        let gate = Gate::default();
        let mut output = Output::start(Box::new(gate.clone())).unwrap();
        let started = Instant::now();
        output.write(b"frame one".to_vec()).unwrap();
        assert!(output.writing(), "the next frame waits for this one");
        assert!(started.elapsed() < Duration::from_secs(1), "handing a frame over does not wait for the terminal");
        // Putting the terminal back gives up instead of waiting for ever.
        let chunks = output.chunks.clone();
        let started = Instant::now();
        assert!(!Output::finish(&chunks, b"restore".to_vec(), Duration::from_millis(200)));
        assert!(started.elapsed() < Duration::from_secs(2));
        // Once the terminal reads again, everything arrives in order.
        gate.open();
        output.written().await.unwrap();
        assert!(!output.writing());
        for _ in 0..200 {
            if gate.taken().ends_with(b"restore") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(gate.taken(), b"frame onerestore");
    }

    #[tokio::test]
    async fn a_failed_write_is_reported_and_later_frames_are_refused() {
        let mut output = Output::start(Box::new(Broken)).unwrap();
        output.write(b"frame".to_vec()).unwrap();
        assert!(output.written().await.is_err());
        let mut refused = false;
        for _ in 0..200 {
            if output.write(b"next".to_vec()).is_err() {
                refused = true;
                break;
            }
            // Handed over before the thread ended: its result says the terminal is gone.
            assert!(output.written().await.is_err());
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(refused, "the writer ended after the failed write");
        let quiet = Output::start(Box::new(Gate::default())).unwrap();
        assert!(!quiet.writing());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), async {
                let mut quiet = quiet;
                quiet.written().await
            })
            .await
            .is_err(),
            "nothing being written: nothing to wait for"
        );
    }
}
