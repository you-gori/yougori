use crate::{public,wire};
use serde_json::{json,Value};
use std::{io::{IsTerminal,Write},time::Duration};

pub const USAGE:&str="Usage: yougori logs ENV [--cursor CURSOR] [--limit BYTES] [--tail BYTES] [--last-error] [--follow]";
#[derive(Debug)]pub struct Options{pub cursor:Option<String>,pub limit:usize,pub tail:usize,pub follow:bool,pub last_error:bool}
#[derive(Default)]pub(crate) struct TerminalText{state:u8}
impl TerminalText{
    /// Ordinary logs are data, not an interactive terminal protocol. Keep a
    /// streaming state so an OSC clipboard/control escape split across reads
    /// cannot reach the user's terminal. JSON retains its original text.
    pub(crate) fn feed(&mut self,text:&str)->String{
        let mut result=String::with_capacity(text.len());
        for c in text.chars(){match self.state{
            0=>match c{'\x1b'=>self.state=1,'\u{9b}'=>self.state=2,'\u{9d}'|'\u{90}'|'\u{98}'|'\u{9e}'|'\u{9f}'=>self.state=3,'\n'|'\t'=>result.push(c),_ if !c.is_control()=>result.push(c),_=>{}},
            1=>self.state=match c{'['=>2,']'|'P'|'X'|'_'|'^'=>3,_=>0},
            2=>{if ('\u{40}'..='\u{7e}').contains(&c){self.state=0}},
            3=>match c{'\x07'|'\u{9c}'=>self.state=0,'\x1b'=>self.state=4,_=>{}},
            _=>self.state=if c=='\\'{0}else{3},
        }}result
    }
}
pub fn parse(args:&[String])->Result<Options,String>{
    let mut options=Options{cursor:None,limit:16384,tail:16384,follow:false,last_error:false};
    let mut seen=std::collections::HashSet::new();let mut i=0;
    while i<args.len(){
        let flag=args[i].as_str();if !seen.insert(flag){return Err("Log option was specified twice".into());}
        match flag{
            "--follow"=>options.follow=true,
            "--last-error"=>options.last_error=true,
            "--cursor"=>{i+=1;options.cursor=Some(args.get(i).ok_or("--cursor requires the previous nextCursor")?.clone());},
            "--limit"|"--tail"=>{i+=1;let value=args.get(i).and_then(|v|v.parse::<usize>().ok()).ok_or("Log byte count must be a nonnegative integer")?;
                if flag=="--limit"{if !(1..=65536).contains(&value){return Err("Log limit must be 1–65536 bytes".into());}options.limit=value;}
                else{if value>262144{return Err("Log tail must be at most 262144 bytes".into());}options.tail=value;}},
            _=>return Err(USAGE.into()),
        }i+=1;
    }Ok(options)
}
pub async fn read(id:&str,mut options:Options)->Result<Value,String>{
    let mut terminal=TerminalText::default();
    // One Ctrl+C listener for the whole follow, so a press during a request counts too.
    let interrupted=tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    loop{
        let request=public::call("get_environment_log_window",json!({"environmentId":id,"cursor":options.cursor,"limit":options.limit,"tail":options.tail}));
        let mut window=if options.follow{
            tokio::select!{_=&mut interrupted=>return Ok(detached(id,&options)),window=request=>window?}
        }else{request.await?};
        options.cursor=Some(window["nextCursor"].as_str().ok_or("Missing log cursor")?.to_owned());
        if options.last_error{
            let text=window["stdout"].as_str().unwrap_or("");
            let last=text.lines().filter(|line|{let line=line.to_ascii_lowercase();["error","failed","panic","exception"].iter().any(|word|line.contains(word))}).next_back().unwrap_or("").to_owned();
            window["stdout"]=last.into();
        }
        window["id"]=id.into();window["logs"]=window["stdout"].clone();
        if !options.follow{return Ok(window);}
        if std::io::stdout().is_terminal(){print!("{}",terminal.feed(window["stdout"].as_str().unwrap_or("")));std::io::stdout().flush().map_err(|e|e.to_string())?;}
        else{println!("{}",serde_json::to_string(&wire::Response::success(window.clone())).map_err(|e|e.to_string())?);}
        if window["truncated"]==true{continue;}
        tokio::select!{_=&mut interrupted=>return Ok(detached(id,&options)),_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}
/// Following stopped with Ctrl+C: the environment keeps running, and the cursor resumes here.
fn detached(id:&str,options:&Options)->Value{json!({"id":id,"detached":true,"nextCursor":options.cursor,"environmentsRemainRunning":true})}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn log_options_are_bounded_and_cursors_are_opaque(){let options=parse(&["--cursor","opaque","--tail","0","--follow"].map(str::to_owned)).unwrap();assert_eq!(options.cursor.as_deref(),Some("opaque"));assert_eq!(options.tail,0);assert!(options.follow);for args in [vec!["--limit","0"],vec!["--tail","262145"],vec!["--cursor"],vec!["--follow","--follow"]]{assert!(parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());}}
    #[test]fn ordinary_log_windows_cannot_inject_terminal_actions_across_cursors(){let mut text=TerminalText::default();assert_eq!(text.feed("before\x1b]52;c;secret"),"before");assert_eq!(text.feed("clipboard\x07after\x1b[2J\x1b[32m\nnormal\r\x00"),"after\nnormal");assert_eq!(text.feed(" café 日本\n")," café 日本\n");}
}
