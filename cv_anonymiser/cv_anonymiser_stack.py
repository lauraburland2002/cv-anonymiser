from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    CfnOutput,
    aws_apigateway as apigateway,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as _lambda,
    aws_ssm as ssm,
    aws_wafv2 as wafv2,
)
from constructs import Construct


class CvAnonymiserStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # KMS key for SSM SecureString + DynamoDB encryption
        key = kms.Key(
            self,
            "CvAnonymiserKey",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment; change for real prod
        )

        # SSM Parameter Store: rules/lexicon (SecureString)

        from aws_cdk import aws_ssm as ssm

        rules_param = ssm.StringParameter(
            self,
            "RedactionRules",
            parameter_name="/cv-anonymiser/redaction-rules",
            string_value='{"redact":["email","phone"],"salt":"demo-salt-change-me"}',
            type=ssm.ParameterType.SECURE_STRING,
        )

        # DynamoDB audit table (no raw CV stored)
        audit_table = dynamodb.Table(
            self,
            "AuditTable",
            partition_key=dynamodb.Attribute(name="requestId", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment; change for real prod
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=key,
        )

        # Lambda (FastAPI via Mangum) as a CONTAINER IMAGE (easy for CI/CD)
        fn = _lambda.DockerImageFunction(
            self,
            "CvAnonymiserFunction",
            code=_lambda.DockerImageCode.from_image_asset("lambda"),
            memory_size=512,
            timeout=Duration.seconds(15),
            environment={
                "RULES_PARAM_NAME": rules_param.parameter_name,
                "AUDIT_TABLE_NAME": audit_table.table_name,
            },
        )

        # Least privilege permissions
        rules_param.grant_read(fn)
        audit_table.grant_write_data(fn)
        key.grant_decrypt(fn)  # for SecureString decrypt + Dynamo encryption operations

        # API Gateway REST API in front of Lambda
        api = apigateway.LambdaRestApi(
            self,
            "CvAnonymiserApi",
            handler=fn,
            proxy=True,  # FastAPI handles routes
            deploy_options=apigateway.StageOptions(
                stage_name="prod",
                tracing_enabled=True,
                metrics_enabled=True,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
            ),
        )

        # WAFv2 Web ACL (basic managed rules) attached to API Gateway stage
        web_acl = wafv2.CfnWebACL(
            self,
            "ApiWebAcl",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="cv-anonymiser-waf",
                sampled_requests_enabled=True,
            ),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedCommon",
                    priority=0,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                        )
                    ),
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWSManagedCommon",
                        sampled_requests_enabled=True,
                    ),
                )
            ],
        )

        api_stage_arn = f"arn:aws:apigateway:{self.region}::/restapis/{api.rest_api_id}/stages/{api.deployment_stage.stage_name}"

        wafv2.CfnWebACLAssociation(
            self,
            "WebAclAssoc",
            resource_arn=api_stage_arn,
            web_acl_arn=web_acl.attr_arn,
        )

        # Outputs (what your frontend needs)
        CfnOutput(self, "ApiUrl", value=api.url)
        CfnOutput(self, "AuditTableName", value=audit_table.table_name)
        CfnOutput(self, "RulesParamName", value=rules_param.parameter_name)









        
