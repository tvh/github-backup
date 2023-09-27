mod telemetry;

use crate::telemetry::{get_subscriber, init_subscriber};
use std::{error::Error, path::Path, sync::Arc};

use octorust::{auth::Credentials, types::Repository, Client, ClientError};
use secrecy::{ExposeSecret, Secret};
use tokio::{sync::Semaphore, task::spawn_blocking};
use url::Url;

#[derive(serde::Deserialize, Debug, Clone)]
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
    tracing::info!("Found {} repos", repos.len());
    Ok(repos)
}

#[tracing::instrument(name = "Cloning repository", skip(repo), fields(repo=repo.full_name))]
fn clone_repo(configuration: Config, repo: &Repository) -> Result<(), Box<dyn Error>> {
    let root_dir = Path::new(configuration.directory.as_str());
    let repo_path = root_dir.join(repo.full_name.as_str());
    let git_repo = if repo_path.exists() {
        git2::Repository::open(repo_path)?
    } else {
        git2::Repository::init_bare(repo_path)?
    };

    let mut repo_url = Url::parse(repo.html_url.as_str())?;
    // FIXME: Get this via the API
    repo_url
        .set_username("tvh")
        .expect("Unable to set username");
    repo_url
        .set_password(Some(configuration.token.expose_secret().as_str()))
        .expect("unable to set password");

    let repo_url = repo_url.as_str();

    git_repo
        .remote_anonymous(repo_url)?
        .fetch(&["refs/heads/*:refs/heads/*"], None, None)?;

    Ok(())
}

#[tracing::instrument(name = "Cloning repositories", skip(repos))]
async fn clone_repos(configuration: &Config, repos: Vec<Repository>) -> Result<(), Box<dyn Error>> {
    let semaphore = Arc::new(Semaphore::new(5));
    let mut join_handles = Vec::new();
    for repo in repos {
        let permit = semaphore.clone().acquire_owned().await?;
        let configuration = configuration.clone();
        join_handles.push(spawn_blocking(move || {
            let res = clone_repo(configuration, &repo);

            // explicitly own `permit` in the task
            drop(permit);

            res.map_err(|err| format!("{:?}", err))
        }));
    }

    for handle in join_handles {
        handle.await??;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = get_subscriber(
        "github-backup".into(),
        "info,reqwest_tracing=warn".into(),
        std::io::stdout,
    );
    init_subscriber(subscriber);
    let configuration = get_configuration().expect("Failed to read configuration.");
    let repos = list_all_repos(&configuration).await?;

    clone_repos(&configuration, repos).await?;
    Ok(())
}
