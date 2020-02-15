# api-gateway-auth-policy

[![CircleCI](https://circleci.com/gh/diogofcunha/api-gateway-auth-policy.svg?style=svg)](https://circleci.com/gh/diogofcunha/api-gateway-auth-policy)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
![npm](https://img.shields.io/npm/v/api-gateway-auth-policy)

This package aims to solve the problem of generating AWS auth policies for API gateways lambda authorizers.
Authorizers an easy and combinient way to secure your aws lambda invokations, to find more about it consult [aws docs](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html).

Being written in typescript, this package aims to be 100% type safe, avoiding common mistakes and being self documented.

## Install

```shell
yarn add api-gateway-auth-policy
```

## Usage example

The public methods exposed by the api are all chainable.

```typescript
const optionalConfig = {
  region: 'eu-west-1',
  stage: 'production',
  apiId: 'xxxxxxxxxx',
};

const accountId = '12345';

new ApiGatewayAuthPolicy(accountId, optionalConfig)
  .allowMethod(HttpVerb.GET, '/media', {
    StringEquals: {'aws:username': 'johndoe'},
  })
  .allowMethod(HttpVerb.PATCH, '/media')
  .allowMethod(HttpVerb.POST, '/media')
  .denyMethod(HttpVerb.DELETE, '/media')
  .denyMethod(HttpVerb.PUT, '/media', {
    IpAddress: {
      'aws:SourceIp': ['203.0.113.0/24', '2001:DB8:1234:5678::/64'],
    },
  })
  .render('principalId');
```

## Generated policy example

```json
{
  "context": {
    "isSecured": true,
    "name": "diogo"
  },
  "policyDocument": {
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Condition": {
          "StringEquals": {
            "aws:username": "johndoe"
          }
        },
        "Effect": "Allow",
        "Resource": ["arn:aws:execute-api:*:12345:*:*:GET:/media"]
      },
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow",
        "Resource": ["arn:aws:execute-api:*:12345:*:*:PATCH:/media", "arn:aws:execute-api:*:12345:*:*:POST:/media"]
      },
      {
        "Action": "execute-api:Invoke",
        "Condition": {
          "IpAddress": {
            "aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"]
          }
        },
        "Effect": "Deny",
        "Resource": ["arn:aws:execute-api:*:12345:*:*:PUT:/media"]
      },
      {
        "Action": "execute-api:Invoke",
        "Effect": "Deny",
        "Resource": ["arn:aws:execute-api:*:12345:*:*:DELETE:/media"]
      }
    ],
    "Version": "2012-10-17"
  },
  "principalId": "*"
}
```
