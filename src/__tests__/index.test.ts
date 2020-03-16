import ApiGatewayAuthPolicy, {HttpVerb} from '../';

describe('ApiGatewayAuthPolicy', () => {
  test('should render as expected when multiple methods are allowed', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(
      apiGatewayAuthPolicy
        .allowMethod(HttpVerb.GET, '/media')
        .allowMethod(HttpVerb.PATCH, '/media', {
          IpAddress: {
            'aws:SourceIp': ['203.0.113.0/24', '2001:DB8:1234:5678::/64'],
          },
        })
        .allowMethod(HttpVerb.POST, '/media')
        .allowMethod(HttpVerb.DELETE, '/media', {
          StringEquals: {'aws:username': 'johndoe'},
        })
        .allowMethod(HttpVerb.PUT, '/media')
        .render('*'),
    ).toMatchInlineSnapshot(`
      Object {
        "context": undefined,
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "IpAddress": Object {
                  "aws:SourceIp": Array [
                    "203.0.113.0/24",
                    "2001:DB8:1234:5678::/64",
                  ],
                },
              },
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PATCH/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "StringEquals": Object {
                  "aws:username": "johndoe",
                },
              },
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/DELETE/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/GET/media",
                "arn:aws:execute-api:*:12345:*/*/POST/media",
                "arn:aws:execute-api:*:12345:*/*/PUT/media",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });

  test('should render as expected when multiple methods are denied', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(
      apiGatewayAuthPolicy
        .denyMethod(HttpVerb.GET, '/media')
        .denyMethod(HttpVerb.PATCH, '/media', {
          StringEquals: {'aws:username': 'johndoe'},
        })
        .denyMethod(HttpVerb.POST, '/media')
        .denyMethod(HttpVerb.DELETE, '/media')
        .denyMethod(HttpVerb.PUT, '/media')
        .render('*'),
    ).toMatchInlineSnapshot(`
      Object {
        "context": undefined,
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "StringEquals": Object {
                  "aws:username": "johndoe",
                },
              },
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PATCH/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/GET/media",
                "arn:aws:execute-api:*:12345:*/*/POST/media",
                "arn:aws:execute-api:*:12345:*/*/DELETE/media",
                "arn:aws:execute-api:*:12345:*/*/PUT/media",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });

  test('should render as expected when multiple methods are allowed and denied and context is set', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(
      apiGatewayAuthPolicy
        .allowMethod(HttpVerb.GET, '/media', {
          StringEquals: {'aws:username': 'johndoe'},
        })
        .allowMethod(HttpVerb.PATCH, '/media')
        .addValueToContext('isSecured', true)
        .allowMethod(HttpVerb.POST, '/media')
        .denyMethod(HttpVerb.DELETE, '/media')
        .denyMethod(HttpVerb.PUT, '/media', {
          IpAddress: {
            'aws:SourceIp': ['203.0.113.0/24', '2001:DB8:1234:5678::/64'],
          },
        })
        .addValueToContext('name', 'diogo')
        .render('*'),
    ).toMatchInlineSnapshot(`
      Object {
        "context": Object {
          "isSecured": true,
          "name": "diogo",
        },
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "StringEquals": Object {
                  "aws:username": "johndoe",
                },
              },
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/GET/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PATCH/media",
                "arn:aws:execute-api:*:12345:*/*/POST/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "IpAddress": Object {
                  "aws:SourceIp": Array [
                    "203.0.113.0/24",
                    "2001:DB8:1234:5678::/64",
                  ],
                },
              },
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PUT/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/DELETE/media",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });

  test('should render as expected when all methods are allowed', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(apiGatewayAuthPolicy.allowMethod(HttpVerb.ALL, '*').render('*')).toMatchInlineSnapshot(`
      Object {
        "context": undefined,
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/*/*",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });

  test('should render as expected when all methods are denied', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(apiGatewayAuthPolicy.denyMethod(HttpVerb.ALL, '*').render('*')).toMatchInlineSnapshot(`
      Object {
        "context": undefined,
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/*/*",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });

  test('should render as expected when multiple methods are allowed and denied', () => {
    const apiGatewayAuthPolicy = new ApiGatewayAuthPolicy('12345');

    expect(
      apiGatewayAuthPolicy
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
        .render('*'),
    ).toMatchInlineSnapshot(`
      Object {
        "context": undefined,
        "policyDocument": Object {
          "Statement": Array [
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "StringEquals": Object {
                  "aws:username": "johndoe",
                },
              },
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/GET/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Allow",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PATCH/media",
                "arn:aws:execute-api:*:12345:*/*/POST/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Condition": Object {
                "IpAddress": Object {
                  "aws:SourceIp": Array [
                    "203.0.113.0/24",
                    "2001:DB8:1234:5678::/64",
                  ],
                },
              },
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/PUT/media",
              ],
            },
            Object {
              "Action": "execute-api:Invoke",
              "Effect": "Deny",
              "Resource": Array [
                "arn:aws:execute-api:*:12345:*/*/DELETE/media",
              ],
            },
          ],
          "Version": "2012-10-17",
        },
        "principalId": "*",
      }
    `);
  });
});
