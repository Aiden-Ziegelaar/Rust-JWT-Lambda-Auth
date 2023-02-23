use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerRequest, ApiGatewayCustomAuthorizerResponse, ApiGatewayCustomAuthorizerPolicy, IamPolicyStatement};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};

static POLICY_VERSION: &str = "2012-10-17";

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
    
    event.context.

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

struct APIGatewayPolicyBuilder {
    region: String,
    aws_account_id: String,
    rest_api_id: String,
    stage: String,
    policy: ApiGatewayCustomAuthorizerPolicy,
}

#[derive(Serialize, Deserialize)]
enum Effect {
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize)]
enum Method {
    All,
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch
}


impl APIGatewayPolicyBuilder {
    pub fn new(
        region: &str,
        account_id: &str,
        api_id: &str,
        stage: &str,
    ) -> APIGatewayPolicyBuilder {
        Self {
            region: region.to_string(),
            aws_account_id: account_id.to_string(),
            rest_api_id: api_id.to_string(),
            stage: stage.to_string(),
            policy: ApiGatewayCustomAuthorizerPolicy {
                version: Some(POLICY_VERSION.to_string()),
                statement: vec![],
            },
        }
    }

    pub fn add_method<T: Into<String>>(
        mut self,
        effect: Effect,
        method: Method,
        resource: T,
    ) -> Self {
        let resource_arn = format!(
            "arn:aws:execute-api:{}:{}:{}/{}/{}/{}",
            &self.region,
            &self.aws_account_id,
            &self.rest_api_id,
            &self.stage,
            serde_json::to_string(&method).unwrap(),
            resource.into().trim_start_matches("/")
        );

        let stmt = IamPolicyStatement {
            effect: Some(serde_json::to_string(&effect).unwrap()),
            action: vec!["execute-api:Invoke".to_string()],
            resource: vec![resource_arn],
        };

        self.policy.statement.push(stmt);
        self
    }

    pub fn allow_all_methods(self) -> Self {
        self.add_method(Effect::Allow, Method::All, "*")
    }

    pub fn deny_all_methods(self) -> Self {
        self.add_method(Effect::Deny, Method::All, "*")
    }

    pub fn allow_method(self, method: Method, resource: String) -> Self {
        self.add_method(Effect::Allow, method, resource)
    }

    pub fn deny_method(self, method: Method, resource: String) -> Self {
        self.add_method(Effect::Deny, method, resource)
    }

    // Creates and executes a new child thread.
    pub fn build(self) -> ApiGatewayCustomAuthorizerPolicy {
        self.policy
    }
}