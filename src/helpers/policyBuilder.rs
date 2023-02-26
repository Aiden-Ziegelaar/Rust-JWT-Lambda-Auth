use serde::{Deserialize, Serialize};
use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, IamPolicyStatement};

static POLICY_VERSION: &str = "2012-10-17";
pub struct APIGatewayPolicyBuilder {
  region: String,
  aws_account_id: String,
  rest_api_id: String,
  stage: String,
  policy: ApiGatewayCustomAuthorizerPolicy,
}

#[derive(Serialize, Deserialize)]
pub enum Effect {
  Allow,
  Deny,
}

#[derive(Serialize, Deserialize)]
pub enum Method {
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

}