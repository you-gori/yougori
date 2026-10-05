use crate::{client, public::call};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};
pub const REFERENCE: &str = "huggingface-model-downloads";

fn hidden_token() -> Result<String, String> {
    use crossterm::event::{read, Event, KeyCode, KeyEventKind, KeyModifiers};
    struct Raw;
    impl Drop for Raw { fn drop(&mut self) { let _=crossterm::terminal::disable_raw_mode(); } }
    eprintln!("Create a read token at https://huggingface.co/settings/tokens. Accept gated models' access conditions on their pages.");
    eprint!("Hugging Face token (hidden): ");
    std::io::stderr().flush().map_err(|_|"Cannot prompt for the token")?;
    crossterm::terminal::enable_raw_mode().map_err(|_|"Cannot read a hidden token")?;
    let _raw=Raw;
    let mut value=String::new();
    loop {
        if let Event::Key(key)=read().map_err(|_|"Cannot read the token")? {
            if key.kind==KeyEventKind::Release {continue}
            match key.code {
                KeyCode::Enter=>{eprintln!("\r");return Ok(value)},
                KeyCode::Esc=>return Err("Hugging Face login cancelled".into()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>return Err("Hugging Face login cancelled".into()),
                KeyCode::Backspace=>{value.pop();},
                KeyCode::Char(c) if c.is_ascii_alphanumeric()||c=='_'=>{if value.len()<1024{value.push(c)}},
                _=>{},
            }
        }
    }
}

fn private_stdin(input: &mut impl Read) -> Result<String,String> {
    let mut bytes=Vec::new();
    input.take(4097).read_to_end(&mut bytes).map_err(|_|"Cannot read the private token input")?;
    if bytes.len()>4096{return Err("Token input exceeds 4 KiB".into())}
    let value:Value=serde_json::from_slice(&bytes).map_err(|_|"Supply private JSON containing only value")?;
    if value.as_object().is_none_or(|o|o.len()!=1){return Err("Supply private JSON containing only value".into())}
    value["value"].as_str().map(str::to_owned).ok_or_else(||"Token value must be a string".into())
}

pub async fn run(args: &[String]) -> Result<Value,String> {
    let action=args.first().map(String::as_str).unwrap_or("status");
    match (action,&args[1.min(args.len())..]) {
        ("status",[])=>{client::start(None).await?;call("model_huggingface_status",json!({})).await},
        ("logout",[])=>{client::start(None).await?;call("delete_deployment_secret",json!({"name":REFERENCE})).await},
        ("login",flags)=>{
            let token=match flags {
                [] if std::io::stdin().is_terminal()=>hidden_token()?,
                []=>private_stdin(&mut std::io::stdin().lock())?,
                [flag,path] if flag=="--file"&&path=="-"=>private_stdin(&mut std::io::stdin().lock())?,
                _=>return Err("Usage: yougori model auth login [--file -] | status | logout. Never pass a token as an argument.".into()),
            };
            if !token.starts_with("hf_") || !(12..=1024).contains(&token.len()) || !token.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_') {
                return Err("Enter a valid Hugging Face read token beginning with hf_. The value was withheld.".into());
            }
            client::start(None).await?;
            call("set_deployment_secret",json!({"name":REFERENCE,"value":token})).await?;
            Ok(json!({"configured":true,"storage":"OS credential vault","message":"Read token saved for the CLI and App. Gated model access must be approved on Hugging Face."}))
        },
        _=>Err("Usage: yougori model auth login [--file -] | status | logout".into()),
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn token_input_is_bounded_and_never_echoed_in_errors() {
        assert_eq!(private_stdin(&mut br#"{"value":"hf_private_token"}"#.as_slice()).unwrap(),"hf_private_token");
        for input in [b"hf_private_token".to_vec(),br#"{"value":"hf_private_token","extra":1}"#.to_vec(),vec![b'x';4097]] {
            let error=private_stdin(&mut input.as_slice()).unwrap_err();
            assert!(!error.contains("hf_private_token"));
        }
    }
}
