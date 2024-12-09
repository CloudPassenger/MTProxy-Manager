use anyhow::{Context, Result};
use chrono::Local;
use local_ip_address::local_ip;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    time::sleep,
};

const CONFIGURATION_FILEPATH: &str = "/configuration.json";
const PROXY_LIST_FILEPATH: &str = "/server/proxy.conf";
const SECRET_FILEPATH: &str = "/server/secret";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Configuration {
    keys: Vec<String>,
    new_keys: usize,
    update_hours: u64,
    ip: String,
    url: String,
    port: u16,
    fake_tls_domain: String,
    port_stats: u16,
    tag: String,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            new_keys: 1,
            update_hours: 12,
            ip: String::new(),
            url: String::new(),
            port: 4000,
            fake_tls_domain: String::new(),
            port_stats: 80,
            tag: String::new(),
        }
    }
}

async fn download(path: impl AsRef<Path>, source_url: &str) -> Result<bool> {
    let response = reqwest::get(source_url).await?;
    
    if response.status().is_success() {
        let mut file = File::create(path.as_ref()).await?;
        let content = response.bytes().await?;
        file.write_all(&content).await?;
        
        let size = fs::metadata(path.as_ref()).await?.len();
        println!("Download to {}: {}b", path.as_ref().display(), size);
        Ok(true)
    } else {
        println!(
            "Download to {} failed: {}",
            path.as_ref().display(),
            response.status()
        );
        Ok(false)
    }
}

async fn update_remote_configurations(retry_minutes: u64) -> Result<bool> {
    println!("Downloading remote configuration...");
    loop {
        let result = tokio::try_join!(
            download(SECRET_FILEPATH, "https://core.telegram.org/getProxySecret"),
            download(PROXY_LIST_FILEPATH, "https://core.telegram.org/getProxyConfig")
        );

        match result {
            Ok((true, true)) => return Ok(true),
            Err(e) => println!("Download failed with an exception: {}", e),
            _ => println!("Download failed"),
        }

        println!("Retrying download in {} minutes.", retry_minutes);
        sleep(Duration::from_secs(retry_minutes * 60)).await;
    }
}

fn generate_key() -> String {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    hex::encode(key)
}

struct MtprotoProxy {
    process: tokio::process::Child,
    start_time: Instant,
    update_interval: Duration,
}

impl MtprotoProxy {
    async fn new(command: &str, update_hours: u64) -> Result<Self> {
        let process = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .spawn()
            .context("Failed to start mtproto-proxy")?;

        Ok(Self {
            process,
            start_time: Instant::now(),
            update_interval: Duration::from_secs(update_hours * 3600),
        })
    }

    fn time_left(&self) -> Duration {
        let elapsed = self.start_time.elapsed();
        if elapsed >= self.update_interval {
            Duration::from_secs(0)
        } else {
            self.update_interval - elapsed
        }
    }

    async fn terminate(&mut self) -> Result<()> {
        if let Some(pid) = self.process.id() {
            // 首先尝试使用 SIGTERM 终止进程
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            
            // 等待进程终止，最多等待20秒
            match tokio::time::timeout(
                Duration::from_secs(20),
                self.process.wait()
            ).await {
                Ok(Ok(_)) => {
                    println!("Process terminated gracefully");
                }
                _ => {
                    // 如果进程没有正常终止，使用 SIGKILL
                    println!("Process did not terminate gracefully, using SIGKILL");
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    // 等待进程被强制终止
                    self.process.wait().await?;
                }
            }
        }
        
        Ok(())
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    // 读取配置文件
    let mut config: Configuration = match fs::read_to_string(CONFIGURATION_FILEPATH).await {
        Ok(content) => serde_json::from_str(&content)?,
        Err(_) => {
            println!("Configuration file was not found. Please, check the documentation on how to mount the file.");
            std::process::exit(1);
        }
    };

    // 生成新密钥
    for _ in 0..config.new_keys {
        config.keys.push(generate_key());
    }

    // 构建命令
    let mut command = String::from("/server/mtproto-proxy -u nobody");
    command.push_str(&format!(" -H {}", config.port));

    if config.port_stats > 0 {
        println!("Serving HTTP stats on {} port. Accessible only via loopback", config.port_stats);
        command.push_str(&format!(" -p {} --http-stats", config.port_stats));
    }

    if !config.tag.is_empty() {
        println!("Advertising tag configured: {}", config.tag);
        command.push_str(&format!(" -P {}", config.tag));
    }

    // 处理 Fake-TLS Domain
    let fake_tls_hex = if !config.fake_tls_domain.is_empty() {
        println!("Using {} for FakeTLS", config.fake_tls_domain);
        command.push_str(&format!(" -D {}", config.fake_tls_domain));
        Some(hex::encode(config.fake_tls_domain.as_bytes()))
    } else {
        None
    };

    // NAT 配置
    if !config.ip.is_empty() {
        let local_ip = local_ip()?;
        if local_ip.to_string() != config.ip {
            println!(
                "Configuring server to work behind the NAT: local {} vs global {}",
                local_ip, config.ip
            );
            command.push_str(&format!(" --nat-info {}:{}", local_ip, config.ip));
        }
    }

    // 打印客户端密钥和邀请链接
    if config.url.is_empty() {
        println!("No server url or ip has been provided. Invite links will not be generated.");
    }
    println!("----------");
    for key in &config.keys {
        println!("Key: {}", key);
        if !config.url.is_empty() {
            if let Some(ref tls_hex) = fake_tls_hex {
                println!(
                    "tg://proxy?server={}&port={}&secret=ee{}{}",
                    config.url, config.port, key, tls_hex
                );
            } else {
                println!(
                    "tg://proxy?server={}&port={}&secret=dd{}",
                    config.url, config.port, key
                );
            }
        }
        println!("----------");
        command.push_str(&format!(" -S {}", key));
    }

    // 添加配置文件路径
    command.push_str(&format!(" --aes-pwd {} {}", SECRET_FILEPATH, PROXY_LIST_FILEPATH));

    // 更新配置文件
    config.new_keys = 0;
    let config_json = serde_json::to_string_pretty(&config)?;
    fs::write(CONFIGURATION_FILEPATH, config_json).await?;
    println!(
        "Configuration file updated: {}b",
        fs::metadata(CONFIGURATION_FILEPATH).await?.len()
    );

    // 首次更新配置
    update_remote_configurations(1).await?;

    // 主循环
    loop {
        let mut proxy = MtprotoProxy::new(&command, config.update_hours).await?;
        
        println!(
            "Launching at {}:\n{}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            command
        );
        println!(
            "Server will be interrupted after {:?}",
            proxy.time_left()
        );
        println!("------------------------------------------------------");
    
        tokio::time::sleep(proxy.time_left()).await;
        
        println!("Requesting new configuration");
        update_remote_configurations(30).await?;
        
        println!("Restarting service process...");
        if let Err(e) = proxy.terminate().await {
            println!("Warning! Server termination failed: {}", e);
        }
        println!("------------------------------------------------------");
    }
}
