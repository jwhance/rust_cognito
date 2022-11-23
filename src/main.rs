use std::env;
use std::io;
use std::io::Write;

use aws_sdk_cognitoidentityprovider as cognitoidentityprovider;
use clap::Parser;
use cognitoidentityprovider::{
    error::AdminInitiateAuthError, model::AuthFlowType, output::AdminInitiateAuthOutput,
    types::SdkError, Error,
};
use rpassword::read_password;
use serde_json::Value;

//
// Example of how to make an AWS Cognito call and retrieve a JWT in Rust
//

#[tokio::main]
async fn main() -> Result<(), Error> {
    // This example uses the AdminUserPasswordAuth flow which needs a Cognito user pool, a
    // app client id, a username, and a password.
    // The userpool and the client id are stored in a JSON file that looks like:
    //
    // {
    // 	"user_pool_id": "us-east-XXXXXXX",
    // 	"client_id": "YYYYYYYYYY"
    // }
    //
    // This example assumes Windows and its HOMEPATH env variable
    //
    let config_path = env::var("HOMEPATH").unwrap() + "\\.aws\\cognito_pool.json";
    println!("Config Path: {}", config_path);

    // Get the JSON config and assign to variables for use
    let config_text = read_cognito_config(&config_path);

    let user_pool_id = config_text["user_pool_id"].as_str().unwrap();
    let client_id = config_text["client_id"].as_str().unwrap();

    // Parse the command line args, if username and/or password are not supplied, they will be queried from the user
    let args = Args::parse();

    // Prompt user for username and password if not on the command line
    let mut username = args.username;
    if "NONE".eq(&username) {
        username = get_username_or_password("Username: ", false);
    }

    let mut password = args.password;
    if "NONE".eq(&password) {
        password = get_username_or_password("Password: ", true);
    }

    // Call Cognito with username/password and return an AdminInitiateAuthOutput result
    let cognito_result = make_cognito_call(&username, &password, &user_pool_id, &client_id).await;

    // Print the id_token field from the result
    println!(
        "JWT:\n{}",
        cognito_result
            .unwrap()
            .authentication_result()
            .unwrap()
            .id_token()
            .unwrap()
    );

    Ok(())
}

async fn make_cognito_call(
    username: &str,
    password: &str,
    user_pool_id: &str,
    client_id: &str,
) -> Result<AdminInitiateAuthOutput, SdkError<AdminInitiateAuthError>> {
    //
    // The AdminInitiateAuth API required AWS credentials.  In this case the default credentials from .aws are used
    //
    let config = aws_config::load_from_env().await;
    let client = cognitoidentityprovider::Client::new(&config);
    let result = client
        .admin_initiate_auth()
        .user_pool_id(user_pool_id)
        .client_id(client_id)
        .auth_flow(AuthFlowType::AdminUserPasswordAuth)
        .auth_parameters("USERNAME", username)
        .auth_parameters("PASSWORD", password)
        .send()
        .await;

    result
}

fn get_username_or_password(prompt: &str, is_password: bool) -> String {
    if !is_password {
        let mut line = String::new();
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut line).unwrap();
        (&line.trim()).to_string()
    } else {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        read_password().unwrap()
    }
}

fn read_cognito_config(filename: &str) -> Value {
    let config_text = std::fs::read_to_string(&filename).unwrap();
    serde_json::from_str::<Value>(&config_text).unwrap()
}

// Struct to hold parsed command line args
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Username to login
    #[arg(short, long, default_value = "NONE")]
    username: String,

    /// Password
    #[arg(short, long, default_value = "NONE")]
    password: String,
}
