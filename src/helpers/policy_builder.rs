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

  fn add_method<T: Into<String>>(
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
          serde_variant::to_variant_name(&method).unwrap().to_string(),
          resource.into().trim_start_matches('/')
      );

      let stmt = IamPolicyStatement {
          effect: Some(serde_variant::to_variant_name(&effect).unwrap().to_string()),
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

  pub fn get_policy_document(self) -> ApiGatewayCustomAuthorizerPolicy {
      self.policy
  }
}

#[cfg(test)]
mod tests {
    use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, IamPolicyStatement};

    use super::APIGatewayPolicyBuilder;

    #[test]
    fn allow_access_to_specific_resource() {
        let mut policy_builder = APIGatewayPolicyBuilder::new(
            "us-east-1",
            "123456789012",
            "api-id",
            "dev",
        );
        policy_builder = policy_builder.allow_method(super::Method::All, "testResource/subResource".to_string());
        assert_eq!(policy_builder.get_policy_document(), ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                effect: Some("Allow".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec!["arn:aws:execute-api:us-east-1:123456789012:api-id/dev/All/testResource/subResource".to_string()],
            }]
        });
    }

    #[test]
    fn deny_access_to_specific_resource() {
        let mut policy_builder = APIGatewayPolicyBuilder::new(
            "us-east-1",
            "123456789012",
            "api-id",
            "dev",
        );
        policy_builder = policy_builder.deny_method(super::Method::All, "testResource/subResource".to_string());
        assert_eq!(policy_builder.policy, ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                effect: Some("Deny".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec!["arn:aws:execute-api:us-east-1:123456789012:api-id/dev/All/testResource/subResource".to_string()],
            }]
        });
    }

    #[test]
    fn allow_access_to_all_resources() {
        let mut policy_builder = APIGatewayPolicyBuilder::new(
            "us-east-1",
            "123456789012",
            "api-id",
            "dev",
        );
        policy_builder = policy_builder.allow_all_methods();
        assert_eq!(policy_builder.policy, ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                effect: Some("Allow".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec!["arn:aws:execute-api:us-east-1:123456789012:api-id/dev/All/*".to_string()],
            }]
        });
    }

    #[test]
    fn deny_access_to_all_resources() {
        let mut policy_builder = APIGatewayPolicyBuilder::new(
            "us-east-1",
            "123456789012",
            "api-id",
            "dev",
        );
        policy_builder = policy_builder.deny_all_methods();
        assert_eq!(policy_builder.policy, ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                effect: Some("Deny".to_string()),
                action: vec!["execute-api:Invoke".to_string()],
                resource: vec!["arn:aws:execute-api:us-east-1:123456789012:api-id/dev/All/*".to_string()],
            }]
        });
    }
}