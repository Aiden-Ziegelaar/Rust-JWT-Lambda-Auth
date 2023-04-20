pub(crate) mod helpers;

use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerRequest, ApiGatewayCustomAuthorizerResponse, ApiGatewayCustomAuthorizerPolicy};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};

use helpers::{policy_builder::APIGatewayPolicyBuilder, jwt_validation::{JwksCache, validate_jwt}};
use serde_json::json;

use lazy_static::lazy_static; // 1.4.0
use std::sync::Mutex;

lazy_static! {
    static ref CACHE: Mutex<JwksCache> = Mutex::new(JwksCache::new(std::env::var("JWKS_URL".to_string()).unwrap()));
}

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

    let cache = &mut CACHE.lock().expect("Could not lock mutex");

    let validation: jsonwebtoken::Validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);

    return match validate_jwt(event.payload.authorization_token.unwrap(), cache, &validation) {
        Ok(_) => {
            let policy_builder_instance = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage);
            let response = ApiGatewayCustomAuthorizerResponse {
                principal_id: Some("user".to_string()),
                policy_document: policy_builder_instance.allow_all_methods().get_policy_document(),
                context: json!({}),
                usage_identifier_key: None,
            };
            Ok(response)
        },
        Err(_) => {
            let policy_builder_instance = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage);
            let response = ApiGatewayCustomAuthorizerResponse {
                principal_id: Some("user".to_string()),
                policy_document: policy_builder_instance.allow_all_methods().get_policy_document(),
                context: json!({}),
                usage_identifier_key: None,
            };
            Ok(response)
        }
    }
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
