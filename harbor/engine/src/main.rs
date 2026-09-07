use anyhow::{Context, Result, bail};
use harbor_engine::{config::Config, engine::Engine};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let isolated = arguments.iter().any(|argument| argument == "--isolated");
    let modes: Vec<&str> = arguments
        .iter()
        .filter(|argument| argument.as_str() != "--isolated")
        .map(String::as_str)
        .collect();
    if arguments.len() > 2
        || modes.len() > 1
        || arguments
            .iter()
            .filter(|argument| argument.as_str() == "--isolated")
            .count()
            > 1
        || modes
            .iter()
            .any(|mode| !matches!(*mode, "--default-config" | "--validate-tun"))
    {
        bail!("Invalid Harbor engine arguments");
    }
    if modes.first() == Some(&"--default-config") {
        println!("{}", serde_json::to_string_pretty(&Config::default())?);
        return Ok(());
    }
    #[cfg(windows)]
    if modes.first() == Some(&"--validate-tun") {
        if isolated {
            bail!("Isolated mode prohibits native TUN validation");
        }
        println!("{}", harbor_engine::native_tun::validate_isolated().await?);
        return Ok(());
    }
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut engine: Option<Arc<Engine>> = None;
    let (output, mut responses) = tokio::sync::mpsc::channel::<Value>(128);
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(response) = responses.recv().await {
            stdout.write_all(format!("{response}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut requests = tokio::task::JoinSet::new();
    let mut verification_cancel = tokio_util::sync::CancellationToken::new();
    loop {
        let mut line = zeroize::Zeroizing::new(Vec::new());
        let n = (&mut reader)
            .take(2 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .await?;
        if n == 0 {
            break;
        }
        if n > 2 * 1024 * 1024 {
            bail!("Command exceeds 2 MiB");
        }
        let mut request: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(e) => {
                let response = json!({"id":null,"ok":false,"error":format!("Invalid JSON: {e}")});
                output.send(response).await?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let command = request
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if command == "verify" || command == "preflight" {
            while requests.try_join_next().is_some() {}
            let parsed: Result<(Config, String)> = (|| {
                Ok((
                    serde_json::from_value(request["config"].clone())?,
                    if command == "preflight" {
                        String::new()
                    } else {
                        request["outbound"]
                            .as_str()
                            .context("Missing outbound")?
                            .to_string()
                    },
                ))
            })();
            wipe(&mut request);
            if requests.len() >= 2 {
                output
                    .send(json!({"id":id,"ok":false,"error":"A verification is already queued"}))
                    .await?;
                continue;
            }
            let egress = engine.as_ref().map(|e| e.resolver.egress.clone());
            let output = output.clone();
            let cancelled = verification_cancel.clone();
            requests.spawn(async move {
                let result = tokio::select! {
                    _ = cancelled.cancelled() => Err(anyhow::anyhow!("Verification cancelled")),
                    result = async { match parsed {
                        Ok((config, outbound)) => if command == "preflight" {
                            harbor_engine::verification::preflight(config).await
                        } else {
                            match egress.map(Ok).unwrap_or_else(|| harbor_engine::net::Egress::configured(config.egress_mode).map(Arc::new)) {
                                Ok(egress) => harbor_engine::verification::verify(config, outbound, egress).await,
                                Err(error) => Err(error),
                            }
                        },
                        Err(error) => Err(error),
                    }} => result,
                };
                let response = match result {
                    Ok(value) => json!({"id":id,"ok":true,"result":value}),
                    Err(error) => json!({"id":id,"ok":false,"error":format!("{error:#}")}),
                };
                let _ = output.send(response).await;
            });
            continue;
        }
        if command == "probe" {
            wipe(&mut request);
            while requests.try_join_next().is_some() {}
            if requests.len() >= 2 {
                output
                    .send(json!({"id":id,"ok":false,"error":"A node probe is already queued"}))
                    .await?;
                continue;
            }
            let e = engine.clone();
            let output = output.clone();
            requests.spawn(async move {let response=if let Some(e)=e{tokio::select!{_=e.cancel.cancelled()=>json!({"id":id,"ok":false,"error":"Engine stopped"}),result=e.probe()=>json!({"id":id,"ok":true,"result":result})}}else{json!({"id":id,"ok":false,"error":"Engine is stopped"})};let _=output.send(response).await;});
            while requests.try_join_next().is_some() {}
            continue;
        }
        let result:Result<Value>=async{match command.as_str() {
            "default_config"=>Ok(serde_json::to_value(Config::default())?),
            "validate"=>{let c:Config=serde_json::from_value(request["config"].clone())?;c.validate()?;Ok(json!({"valid":true}))},
            "rehearse"=>{let before:Config=serde_json::from_value(request["before"].clone())?;let after:Config=serde_json::from_value(request["after"].clone())?;let targets:Vec<harbor_engine::rehearsal::Target>=serde_json::from_value(request["targets"].clone())?;harbor_engine::rehearsal::compare(&before,&after,&targets)},
            "start"=>{if engine.is_some(){bail!("Engine already running");}let config:Config=serde_json::from_value(request["config"].clone())?;if isolated && config.tun {bail!("Isolated mode prohibits TUN and route changes");}let e=Engine::start(config).await?;let snapshot=e.snapshot();engine=Some(e);Ok(snapshot)},
            "stop"=>{verification_cancel.cancel();verification_cancel=tokio_util::sync::CancellationToken::new();if let Some(e)=engine.take(){e.stop().await?;tokio::time::sleep(Duration::from_millis(150)).await;}Ok(json!({"running":false}))},
            "snapshot"=>Ok(engine.as_ref().map(|e|e.snapshot()).unwrap_or(json!({"running":false}))),
            "configure"=>{let e=engine.as_ref().context("Engine is stopped")?;let c=serde_json::from_value(request["config"].clone())?;Ok(json!({"generation":e.configure(c)?}))},
            "explain"=>{let e=engine.as_ref().context("Start the engine to evaluate a route")?;let c=e.current.load_full();let host=request["host"].as_str().context("Missing host")?;let port=request["port"].as_u64().unwrap_or(443);if port==0||port>65535{bail!("Invalid port");}Ok(serde_json::to_value(e.decision(&c,host,port as u16,request["protocol"].as_str().unwrap_or("tcp"))?)?)},

            "clear_dns"=>{engine.as_ref().context("Engine is stopped")?.resolver.clear();Ok(json!({"cleared":true}))},
            "clear_history"=>{engine.as_ref().context("Engine is stopped")?.telemetry.clear_history();Ok(json!({"cleared":true}))},
            "close_flow"=>Ok(json!({"closed":engine.as_ref().context("Engine is stopped")?.close_flow(request["flowId"].as_u64().context("Missing flow ID")?)})),
            "shutdown"=>Ok(json!({"shutdown":true})),
            _=>bail!("Unknown command"),
        }}.await;
        wipe(&mut request);
        let response = match result {
            Ok(value) => json!({"id":id,"ok":true,"result":value}),
            Err(error) => json!({"id":id,"ok":false,"error":format!("{error:#}")}),
        };
        output.send(response).await?;
        if command == "shutdown" {
            break;
        }
    }
    if let Some(e) = engine {
        e.stop().await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    drop(output);
    writer.await??;
    Ok(())
}

fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(values) => values.values_mut().for_each(wipe),
        _ => {}
    }
}
