mod helpers;
use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerRequest, ApiGatewayCustomAuthorizerResponse};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};

use helpers::policyBuilder::{APIGatewayPolicyBuilder};

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(event: LambdaEvent<ApiGatewayCustomAuthorizerRequest>) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let tmp: Vec<&str> = event.payload.method_arn.unwrap().split(":").collect();
    let api_gateway_arn_tmp: Vec<&str> = tmp[5].split("/").collect();
    let aws_account_id = tmp[4];
    let region = tmp[3];
    let rest_api_id = api_gateway_arn_tmp[0];
    let stage = api_gateway_arn_tmp[1];
    
    let policyBuilderInstance = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage);

    

    Ok()
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
