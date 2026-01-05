from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    CfnOutput,
    aws_apigateway as apigateway,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_codedeploy as codedeploy,
    aws_dynamodb as dynamodb,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_ssm as ssm,
    aws_wafv2 as wafv2,
    aws_cloudtrail as cloudtrail,
)
from constructs import Construct


class CvAnonymiserStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # -------------------------
        # Alerts destination (SNS)
        # -------------------------
        alert_topic = sns.Topic(self, "CvAnonAlertsTopic")
        alert_topic.add_subscription(subs.EmailSubscription("lauraburland@outlook.com"))
        alarm_action = cw_actions.SnsAction(alert_topic)

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
        )

        audit_table = dynamodb.Table(
            self,
            "AuditTable",
            partition_key=dynamodb.Attribute(
                name="requestId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=key,
        )

        # -------------------------
        # Lambda API (FastAPI + Mangum)
        # -------------------------
        cv_lambda = lambda_.Function(
            self,
            "CvAnonymiserFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="app.handler",
            code=lambda_.Code.from_asset("lambda"),
            timeout=Duration.seconds(10),
            memory_size=512,
            log_retention=logs.RetentionDays.TWO_WEEKS,
            environment={
                "RULES_PARAM_NAME": rules_param.parameter_name,
                "AUDIT_TABLE_NAME": audit_table.table_name,
                # FRONTEND_ORIGIN set after CloudFront is created below
            },
        )

        rules_param.grant_read(cv_lambda)
        audit_table.grant_write_data(cv_lambda)
        key.grant_decrypt(cv_lambda)

        # -------------------------
        # Canary deployments (Lambda Alias + CodeDeploy)
        # -------------------------
        # Create a new immutable version each deploy
        cv_version = cv_lambda.current_version

        # Alias is what traffic shifts between versions
        live_alias = lambda_.Alias(
            self,
            "CvAnonLiveAlias",
            alias_name="live",
            version=cv_version,
        )

        # -------------------------
        # API Gateway + Access Logs
        # -------------------------
        api_access_log_group = logs.LogGroup(
            self,
            "ApiGatewayAccessLogs",
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # IMPORTANT: point API Gateway at the ALIAS for canary to work
        api = apigateway.LambdaRestApi(
            self,
            "CvAnonymiserApi",
            handler=live_alias,  # <-- changed from cv_lambda to live_alias
            proxy=True,
            deploy_options=apigateway.StageOptions(
                stage_name="prod",
                tracing_enabled=True,
                metrics_enabled=True,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
                access_log_destination=apigateway.LogGroupLogDestination(
                    api_access_log_group
                ),
                access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
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
            auto_delete_objects=True,  # ok for assignment
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

        frontend_origin = f"[https://{distribution.domain_name}]https://{distribution.domain_name}"
        cv_lambda.add_environment("FRONTEND_ORIGIN", frontend_origin)

        s3deploy.BucketDeployment(
            self,
            "DeployFrontend",
            destination_bucket=site_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
            sources=[
                s3deploy.Source.asset("frontend"),
                s3deploy.Source.data(
                    "config.js",
                    f'window.APP_CONFIG={{API_BASE_URL:"{api.url.rstrip("/")}"}};',
                ),
            ],
        )

        # -------------------------
        # CloudTrail (audit: who changed what)
        # -------------------------
        trail_bucket = s3.Bucket(
            self,
            "CloudTrailBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,  # ok for assignment
            auto_delete_objects=True,  # ok for assignment
        )

        cloudtrail.Trail(
            self,
            "CvAnonTrail",
            bucket=trail_bucket,
            is_multi_region_trail=False,
            include_global_service_events=False,
            management_events=cloudtrail.ReadWriteType.ALL,
        )

        # -------------------------
        # Monitoring: Alarms
        # -------------------------
        api_5xx = api.metric_server_error(period=Duration.minutes(1), statistic="sum")
        api_5xx_alarm = cloudwatch.Alarm(
            self,
            "AlarmApi5xx",
            metric=api_5xx,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="API Gateway 5XX errors detected.",
        )
        api_5xx_alarm.add_alarm_action(alarm_action)

        api_latency = api.metric_latency(period=Duration.minutes(5), statistic="p95")
        api_latency_alarm = cloudwatch.Alarm(
            self,
            "AlarmApiLatencyP95",
            metric=api_latency,
            threshold=2000,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="API Gateway p95 latency is high.",
        )
        api_latency_alarm.add_alarm_action(alarm_action)

        lambda_errors_alarm = cloudwatch.Alarm(
            self,
            "AlarmLambdaErrors",
            metric=cv_lambda.metric_errors(period=Duration.minutes(1), statistic="sum"),
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="Lambda errors detected.",
        )
        lambda_errors_alarm.add_alarm_action(alarm_action)

        lambda_throttles_alarm = cloudwatch.Alarm(
            self,
            "AlarmLambdaThrottles",
            metric=cv_lambda.metric_throttles(period=Duration.minutes(1), statistic="sum"),
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="Lambda throttling detected.",
        )
        lambda_throttles_alarm.add_alarm_action(alarm_action)

        lambda_duration_alarm = cloudwatch.Alarm(
            self,
            "AlarmLambdaDurationP95",
            metric=cv_lambda.metric_duration(period=Duration.minutes(5), statistic="p95"),
            threshold=8000,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="Lambda p95 duration approaching timeout.",
        )
        lambda_duration_alarm.add_alarm_action(alarm_action)

        ddb_throttle_alarm = cloudwatch.Alarm(
            self,
            "AlarmDdbUserErrors",
            metric=audit_table.metric_user_errors(
                period=Duration.minutes(1), statistic="sum"
            ),
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="DynamoDB user errors (including throttles) detected.",
        )
        ddb_throttle_alarm.add_alarm_action(alarm_action)

        cf_5xx_alarm = cloudwatch.Alarm(
            self,
            "AlarmCloudFront5xxRate",
            metric=distribution.metric5xx_error_rate(
                period=Duration.minutes(5), statistic="avg"
            ),
            threshold=1.0,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="CloudFront 5xx error rate high.",
        )
        cf_5xx_alarm.add_alarm_action(alarm_action)

        waf_blocked_metric = cloudwatch.Metric(
            namespace="AWS/WAFV2",
            metric_name="BlockedRequests",
            period=Duration.minutes(5),
            statistic="sum",
            dimensions_map={
                "WebACL": "cv-anonymiser-waf",
                "Rule": "ALL",
                "Region": self.region,
            },
        )

        waf_blocked_alarm = cloudwatch.Alarm(
            self,
            "AlarmWafBlockedRequests",
            metric=waf_blocked_metric,
            threshold=50,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
            alarm_description="WAF is blocking an unusual number of requests.",
        )
        waf_blocked_alarm.add_alarm_action(alarm_action)

        # -------------------------
        # Canary deployment group (rollback on alarm)
        # -------------------------
        # If alarms breach during canary, CodeDeploy automatically rolls back alias to prior version.
        codedeploy.LambdaDeploymentGroup(
            self,
            "CvAnonCanaryDeployment",
            alias=live_alias,
            deployment_config=codedeploy.LambdaDeploymentConfig.CANARY_10_PERCENT_5_MINUTES,
            alarms=[
                lambda_errors_alarm,
                api_5xx_alarm,
            ],
        )

        # -------------------------
        # Monitoring: Dashboard
        # -------------------------
        dashboard = cloudwatch.Dashboard(self, "CvAnonDashboard")

        dashboard.add_widgets(
            cloudwatch.GraphWidget(title="API Gateway - 5XX (sum)", left=[api_5xx]),
            cloudwatch.GraphWidget(title="API Gateway - Latency p95 (ms)", left=[api_latency]),
            cloudwatch.GraphWidget(
                title="Lambda - Errors (sum) & Throttles (sum)",
                left=[
                    cv_lambda.metric_errors(period=Duration.minutes(1), statistic="sum"),
                    cv_lambda.metric_throttles(period=Duration.minutes(1), statistic="sum"),
                ],
            ),
            cloudwatch.GraphWidget(
                title="Lambda - Duration p95 (ms)",
                left=[cv_lambda.metric_duration(period=Duration.minutes(5), statistic="p95")],
            ),
            cloudwatch.GraphWidget(
                title="DynamoDB - User Errors (sum)",
                left=[audit_table.metric_user_errors(period=Duration.minutes(1), statistic="sum")],
            ),
            cloudwatch.GraphWidget(
                title="CloudFront - 5xx Error Rate (%)",
                left=[distribution.metric5xx_error_rate(period=Duration.minutes(5), statistic="avg")],
            ),
            cloudwatch.GraphWidget(title="WAF - BlockedRequests (sum)", left=[waf_blocked_metric]),
        )

        # -------------------------
        # Outputs
        # -------------------------
        CfnOutput(self, "ApiUrl", value=api.url)
        CfnOutput(self, "FrontendUrl", value=frontend_origin)
        CfnOutput(self, "AuditTableName", value=audit_table.table_name)
        CfnOutput(self, "RulesParamName", value=rules_param.parameter_name)
        CfnOutput(self, "AlertsTopicArn", value=alert_topic.topic_arn)
        CfnOutput(self, "DashboardName", value=dashboard.dashboard_name)
        CfnOutput(self, "LambdaAliasName", value=live_alias.alias_name)