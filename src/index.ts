export interface AwsConfig {
  /**
   * The API id
   * example xxxxxxxxxx
   * defaults to "*"
   */
  apiId?: string;
  /**
   * The API AWS region
   * example eu-west-1
   * defaults to "*"
   */
  region?: string;
  /**
   * The stage for your api
   * example production
   * defaults to "*"
   */
  stage?: string;
}

export type Condition = {
  [conditionOperator: string]: {
    [conditionKey: string]: string | string[];
  };
};

interface Method {
  effect: Effect;
  resourceArn: string;
  condition: Condition | null;
}

export enum HttpVerb {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  PATCH = 'PATCH',
  HEAD = 'HEAD',
  DELETE = 'DELETE',
  OPTIONS = 'OPTIONS',
  ALL = '*',
}

export enum Effect {
  Allow = 'Allow',
  Deny = 'Deny',
}

export interface Statement {
  Action: 'execute-api:Invoke';
  Effect: Effect;
  Resource: string[];
  Condition?: Condition;
}

export interface PolicyDocument {
  Version: string;
  Statement: Statement[];
}

export type Context = {[prop: string]: string | boolean | number};

export interface AuthResponse {
  principalId: string;
  policyDocument: PolicyDocument;
  context?: Context;
}

const RESOURCE_PATH_REGEX = new RegExp('^[/.a-zA-Z0-9-*]+$');
const ALLOWED_EFFECT_VALUES = new Set(Object.values(Effect));
const ALLOWED_HTTP_VERB_VALUES = new Set(Object.values(HttpVerb));

/**
 * A Policy generator for API Gateway authorizers.
 *
 * new ApiGatewayAuthPolicy('12345')
 *  .allowMethod(HttpVerb.GET, '/media')
 *  .allowMethod(HttpVerb.PATCH, '/media', {
 *    IpAddress: {
 *     'aws:SourceIp': ['203.0.113.0/24', '2001:DB8:1234:5678::/64'],
 *   },
 *  })
 *  .render('*');
 */
export default class ApiGatewayAuthPolicy {
  private readonly _accountId: string;
  private readonly _apiVersion: string = '2012-10-17';
  private readonly _config: AwsConfig;
  private readonly _methods: Method[] = [];
  private _context: Context | undefined;

  constructor(accountId: string, config?: AwsConfig) {
    this._accountId = accountId;
    this._config = {
      apiId: '*',
      region: '*',
      stage: '*',
      ...config,
    };
  }

  private getResourceArn(verb: HttpVerb, resource: string) {
    return `arn:aws:execute-api:${this._config.region}:${this._accountId}:${this._config.apiId}/${this._config.stage}/${verb}/${resource}`;
  }

  private addMethod(effect: Effect, verb: HttpVerb, resource: string, condition?: Condition | null): void {
    if (!ALLOWED_EFFECT_VALUES.has(effect)) {
      throw new Error(`Found invalid effect ${effect}`);
    }

    if (!ALLOWED_HTTP_VERB_VALUES.has(verb)) {
      throw new Error(`Found invalid verb ${verb}`);
    }

    if (!RESOURCE_PATH_REGEX.test(resource)) {
      throw new Error(`Found invalid resource path "${resource}". Paths should match ${RESOURCE_PATH_REGEX}`);
    }

    const cleanedUpResource = resource.startsWith('/') ? resource.substring(1) : resource;

    const resourceArn = this.getResourceArn(verb, cleanedUpResource);

    this._methods.push({
      resourceArn,
      effect,
      condition: condition || null,
    });
  }

  private getStatement(effect: Effect, resource: string[] = [], condition?: Condition | null): Statement {
    const statement: Statement = {
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: resource,
    };

    if (condition) {
      statement.Condition = condition;
    }

    return statement;
  }

  private getStatementsForEffect(effect: Effect): Statement[] {
    const effectMethods = this._methods.filter((m) => m.effect === effect);

    const statements: Statement[] = [];
    const resourcesWithoutCondition: string[] = [];

    effectMethods.forEach((m) => {
      if (m.condition) {
        statements.push(this.getStatement(effect, [m.resourceArn], m.condition));
      } else {
        resourcesWithoutCondition.push(m.resourceArn);
      }
    });

    if (resourcesWithoutCondition.length > 0) {
      statements.push(this.getStatement(effect, resourcesWithoutCondition));
    }

    return statements;
  }

  /**
   * Adds an API Gateway method to the list of allowed
   * methods for the policy, can be used in chain
   */
  public allowMethod(verb: HttpVerb, resource: string, condition?: Condition | null): this {
    this.addMethod(Effect.Allow, verb, resource, condition);

    return this;
  }

  /**
   * Adds an API Gateway method to the list of denied
   * methods for the policy, can be used in chain
   */
  public denyMethod(verb: HttpVerb, resource: string, condition?: Condition | null): this {
    this.addMethod(Effect.Deny, verb, resource, condition);

    return this;
  }

  /**
   * Adds an context key value pair that will later be added into the auth response
   */
  public addValueToContext(key: string, value: string | number | boolean): this {
    if (!this._context) {
      this._context = {};
    }
    this._context[key] = value;

    return this;
  }

  /**
   * Renders a auth response based on the provided principal id and the lists of allowed and denied methods
   * This will generate a policy with two main statements for the effect:
   * One statement for Allow and one statement for Deny.
   * Methods that includes conditions will have their own statement in the policy.
   */
  public render(principalId: string): AuthResponse {
    if (this._methods.length === 0) {
      throw new Error(`The policy has no statements`);
    }

    const policy: AuthResponse = {
      principalId,
      policyDocument: {
        Version: this._apiVersion,
        Statement: [...this.getStatementsForEffect(Effect.Allow), ...this.getStatementsForEffect(Effect.Deny)],
      },
      context: this._context,
    };

    return policy;
  }
}
