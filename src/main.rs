mod telemetry;

use crate::telemetry::{get_subscriber, init_subscriber};
use std::error::Error;

use octorust::{auth::Credentials, types::Repository, Client, ClientError};
use secrecy::{ExposeSecret, Secret};

#[derive(serde::Deserialize, Debug)]
struct Config {
    pub token: Secret<String>,
    pub directory: String,
}

fn get_configuration() -> Result<Config, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let settings = config::Config::builder()
        .add_source(config::File::from(base_path.join("config.json")))
        .build()?;
    settings.try_deserialize::<Config>()
}

#[tracing::instrument(name = "Fetching all repos for user")]
async fn list_all_repos(configuration: &Config) -> Result<Vec<Repository>, ClientError> {
    let github = Client::new(
        String::from("tvh/github-backup"),
        Credentials::Token(String::from(configuration.token.expose_secret())),
    )?;
    let repos = github
        .repos()
        .list_all_for_authenticated_user(
            None,
            "",
            None,
            octorust::types::ReposListOrgSort::FullName,
            octorust::types::Order::Asc,
            None,
            None,
        )
        .await?
        .body;
    Ok(repos)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = get_subscriber("github-backup".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);
    let configuration = get_configuration().expect("Failed to read configuration.");
    let repos = list_all_repos(&configuration).await?;
    println!("{} repos", repos.len());
    Ok(())
}
