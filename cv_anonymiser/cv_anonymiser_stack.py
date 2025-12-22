
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    CfnOutput,
    aws_apigateway as apigateway,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_dynamodb as dynamodb,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_ssm as ssm,
    aws_wafv2 as wafv2,
)
from constructs import Construct


class CvAnonymiserStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # -------------------------
        # Data security primitives
        # -------------------------
        key = kms.Key(
            self,
            "CvAnonymiserKey",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment
        )

        rules_param = ssm.StringParameter(
            self,
            "RedactionRules",
            parameter_name="/cv-anonymiser/redaction-rules",
            string_value='{"redact":["email","phone"],"salt":"demo-salt-change-me"}',
            # NOTE: SecureString "type" is deprecated in CDK v2; use StringParameter + WithDecryption in code.
        )

        audit_table = dynamodb.Table(
            self,
            "AuditTable",
            partition_key=dynamodb.Attribute(name="requestId", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=key,
        )

        # -------------------------
        # Lambda API (FastAPI + Mangum)
        # -------------------------

        cloudfront_origin = "https://{dewzjrqq4bxoq.cloudfront.net"


        cv_lambda = lambda_.Function(
            self,
            "CvAnonymiserFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="app.handler",
            code=lambda_.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            memory_size=512,
            environment={
                "RULES_PARAM_NAME": rules_param.parameter_name,
                "AUDIT_TABLE_NAME": audit_table.table_name,
                "FRONTEND_ORIGIN": cloudfront_origin,
                # FRONTEND_ORIGIN gets set once we create CloudFront below
            },
        )

        rules_param.grant_read(cv_lambda)
        audit_table.grant_write_data(cv_lambda)
        key.grant_decrypt(cv_lambda)

        # -------------------------
        # API Gateway
        # -------------------------

        api = apigateway.LambdaRestApi(
            self,
            "CvAnonymiserApi",
            handler=cv_lambda,
            proxy=True,
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,   # tighten later
                allow_methods=["GET", "POST", "OPTIONS"],
                allow_headers=[
                    "Content-Type",
                    "Authorization",
                    "X-Amz-Date",
                    "X-Api-Key",
                    "X-Amz-Security-Token",
                ],
                max_age=Duration.minutes(10),
            ),
            deploy_options=apigateway.StageOptions(
                stage_name="prod",
                tracing_enabled=True,
                metrics_enabled=True,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
            ),
        )

        # -------------------------
        # WAF on API Gateway stage
        # -------------------------
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

        api_stage_arn = (
            f"arn:aws:apigateway:{self.region}::/restapis/"
            f"{api.rest_api_id}/stages/{api.deployment_stage.stage_name}"
        )

        wafv2.CfnWebACLAssociation(
            self,
            "WebAclAssoc",
            resource_arn=api_stage_arn,
            web_acl_arn=web_acl.attr_arn,
        )

        # -------------------------
        # Frontend: S3 + CloudFront
        # -------------------------
        site_bucket = s3.Bucket(
            self,
            "FrontendBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment
            auto_delete_objects=True,              # ok for assignment
        )

        distribution = cloudfront.Distribution(
            self,
            "FrontendDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            default_root_object="index.html",
            error_responses=[
                # If you later turn this into an SPA, these help avoid 404s on refresh.
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                ),
            ],
        )

        # Lock down CORS to your CloudFront site (good for security marks)
        frontend_origin = f"[https://{distribution.domain_name}]https://{distribution.domain_name}"
        cv_lambda.add_environment("FRONTEND_ORIGIN", frontend_origin)

        # Deploy frontend assets from ./frontend AND generate config.js with the current API URL
        s3deploy.BucketDeployment(
            self,
            "DeployFrontend",
            destination_bucket=site_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
            sources=[
                s3deploy.Source.asset("frontend"),
                # overwrite/ensure config.js always matches deployed API URL
                s3deploy.Source.data(
                    "config.js",
                    f'window.APP_CONFIG={{API_BASE_URL:"{api.url}"}};',
                ),
            ],
        )

        # -------------------------
        # Outputs
        # -------------------------
        CfnOutput(self, "ApiUrl", value=api.url)
        CfnOutput(self, "FrontendUrl", value=frontend_origin)
        CfnOutput(self, "AuditTableName", value=audit_table.table_name)
        CfnOutput(self, "RulesParamName", value=rules_param.parameter_name)