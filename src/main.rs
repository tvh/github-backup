mod telemetry;

use crate::telemetry::{get_subscriber, init_subscriber};

use std::{path::Path, str::FromStr, sync::Arc};

use anyhow::Result;
use chrono::{DateTime, Local, TimeZone};
use cron::Schedule;
use git2::FetchOptions;
use octorust::{
    auth::Credentials,
    types::{Repository, UsersGetByUsernameResponseOneOf},
    Client, ClientError,
};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tokio::{sync::Semaphore, task::JoinSet};

#[derive(serde::Deserialize, Debug, Clone)]
struct Config {
    pub token: Secret<String>,
    pub directory: String,
    #[serde(deserialize_with = "parse_schedule")]
    pub schedule: Option<Schedule>,
}

fn parse_schedule<'de, D>(deserializer: D) -> Result<Option<Schedule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(str) => match Schedule::from_str(str.as_str()) {
            Ok(schedule) => Ok(Some(schedule)),
            Err(err) => Err(serde::de::Error::custom(err)),
        },
        None => Ok(None),
    }
}

fn get_configuration() -> Result<Config, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let mut settings_builder = config::Config::builder();
    let config_path = base_path.join("config.json");
    if config_path.exists() {
        settings_builder = settings_builder.add_source(config::File::from(config_path));
    }
    settings_builder = settings_builder.add_source(
        config::Environment::with_prefix("GITHUB_BACKUP")
            .prefix_separator("_")
            .separator("__"),
    );
    let settings = settings_builder.build()?;
    settings.try_deserialize::<Config>()
}

#[derive(Debug, Clone)]
struct ListRepoResult {
    pub repos: Vec<Repository>,
    pub username: String,
}

#[tracing::instrument(name = "Fetching all repos for user")]
async fn list_all_repos(configuration: &Config) -> Result<ListRepoResult, ClientError> {
    let github = Client::new(
        String::from("tvh/github-backup"),
        Credentials::Token(String::from(configuration.token.expose_secret())),
    )?;
    let user = github.users().get_authenticated().await?.body;
    let username = match user {
        UsersGetByUsernameResponseOneOf::PublicUser(user) => user.login,
        UsersGetByUsernameResponseOneOf::PrivateUser(user) => user.login,
    };
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
    Ok(ListRepoResult {
        repos: repos,
        username: username,
    })
}

#[tracing::instrument(name = "Cloning repository", skip(repo), fields(repo=repo.full_name))]
fn clone_repo(
    configuration: Config,
    user: String,
    root_dir: &Path,
    repo: &Repository,
) -> Result<()> {
    let repo_path = root_dir.join(repo.full_name.as_str());
    let git_repo = if repo_path.exists() {
        tracing::info!("Found existing clone");
        git2::Repository::open(repo_path)?
    } else {
        tracing::info!("Setting up new clone");
        git2::Repository::init_bare(repo_path)?
    };
    let mut origin_remote = git_repo.find_remote("origin").or_else(|_e| {
        git_repo.remote_with_fetch(
            "origin",
            &repo.html_url,
            "+refs/heads/*:refs/remotes/origin/*",
        )
    })?;
    let mut callbacks = git2::RemoteCallbacks::new();
    callbacks.credentials(|_url, _username_from_url, _allowed_types| {
        git2::Cred::userpass_plaintext(user.as_str(), configuration.token.expose_secret().as_str())
    });

    tracing::info!("Doing the fetch");
    origin_remote.fetch(
        &["+refs/heads/*:refs/remotes/origin/*"],
        Some(
            FetchOptions::new()
                .remote_callbacks(callbacks)
                // We assume an external backup for the base directory.
                // Therefore it is better to prune and let the backup handle historic values.
                .prune(git2::FetchPrune::On),
        ),
        None,
    )?;

    Ok(())
}

#[tracing::instrument(name = "Cloning repositories", skip(repos))]
async fn clone_repos(configuration: &Config, repos: ListRepoResult) -> Result<()> {
    let semaphore = Arc::new(Semaphore::new(5));
    let mut join_set = JoinSet::new();
    let root_dir = String::from(shellexpand::full(configuration.directory.as_str())?);
    for repo in repos.repos {
        let permit = semaphore.clone().acquire_owned().await?;
        let configuration = configuration.clone();
        let username = repos.username.clone();
        let root_dir = Path::new(root_dir.as_str()).to_owned();
        join_set.spawn_blocking(move || {
            let res = clone_repo(configuration, username, &root_dir, &repo);

            // explicitly own `permit` in the task
            drop(permit);

            res
        });
    }

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(())) => (),
            Ok(Err(e)) => tracing::error!("{:?}", e),
            Err(e) => tracing::error!("{:?}", e),
        }
    }

    Ok(())
}

#[tracing::instrument]
async fn run(configuration: &Config) -> Result<()> {
    let repos = list_all_repos(configuration).await?;
    clone_repos(configuration, repos).await?;
    Ok(())
}

async fn sleep_until<Z: TimeZone>(t: DateTime<Z>) {
    loop {
        let now = chrono::Utc::now();
        let diff = t.clone().signed_duration_since(now);
        if diff.num_milliseconds() <= 0 {
            return;
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(
                diff.num_milliseconds()
                    .try_into()
                    .expect("failed to convert positive duration"),
            ))
            .await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = get_subscriber(
        "github-backup".into(),
        "info,reqwest_tracing=warn".into(),
        std::io::stdout,
    );
    init_subscriber(subscriber);
    let configuration = get_configuration()?;

    match configuration.clone().schedule {
        None => {
            tracing::info!("No schedule set, running once");
            run(&configuration).await?
        }
        Some(schedule) => {
            tracing::info!("Running with schedule: {}", schedule);
            let upcoming = schedule.upcoming_owned(Local);
            for t in upcoming {
                tracing::info!("Sleeping until {}", t);
                sleep_until(t).await;
                match run(&configuration).await {
                    Ok(()) => {}
                    Err(e) => tracing::error!("Error while running backup: {}", e),
                }
            }
        }
    }
    Ok(())
}
