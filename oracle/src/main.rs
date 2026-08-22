use clap::Parser as _;
use logos_oracle_node::{Cli, run};

#[tokio::main]
async fn main() {
    run(Cli::parse()).await;
}
