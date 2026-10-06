// Public test-recipient helper. Its ephemeral private key is never printed or saved.
fn main() {
    let keys = yougori_cli::confidential::RunnerKeys::generate().unwrap();
    println!(
        "{}",
        keys.descriptor(
            "test".into(),
            "test/model".into(),
            "a".repeat(40),
            "A".repeat(43),
            0
        )
        .recipient
    );
}
