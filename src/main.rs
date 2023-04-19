pub(crate) mod helpers;
#[macro_use]
extern crate lazy_static;
use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerRequest, ApiGatewayCustomAuthorizerResponse, ApiGatewayCustomAuthorizerPolicy};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};


use helpers::{policy_builder::{APIGatewayPolicyBuilder}, jwt_validation::JwksCache};
use serde_json::json;

lazy_static! {
    /// Instantiate JWKS_CACHE to reuse keys between requests
    static ref JWKS_CACHE: JwksCache = JwksCache::new(std::env::var("JWKS_URL").unwrap());
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(event: LambdaEvent<ApiGatewayCustomAuthorizerRequest>) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let method_arn = match event.payload.method_arn {
        Some(arn) => arn,
        None => {
            return Ok(ApiGatewayCustomAuthorizerResponse {
                principal_id: Some("user".to_string()),
                policy_document: ApiGatewayCustomAuthorizerPolicy {
                    version: Some("2012-10-17".to_string()),
                    statement: vec![],
                },
                context: json!({}),
                usage_identifier_key: None,
            })
        }
    };
    let tmp: Vec<&str> = method_arn.split(':').collect();
    let api_gateway_arn_tmp: Vec<&str> = tmp[5].split('/').collect();
    let aws_account_id = tmp[4];
    let region = tmp[3];
    let rest_api_id = api_gateway_arn_tmp[0];
    let stage = api_gateway_arn_tmp[1];
    
    let policy_builder_instance = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage);

    let response = ApiGatewayCustomAuthorizerResponse {
        principal_id: Some("user".to_string()),
        policy_document: policy_builder_instance.get_policy_document(),
        context: json!({}),
        usage_identifier_key: None,
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
