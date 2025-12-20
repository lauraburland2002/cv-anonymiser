from aws_cdk import (
    Stack,
    CfnOutput,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
)
from constructs import Construct


class CvAnonymiserStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Lambda function
        cv_lambda = lambda_.Function(
            self,
            "CvAnonymiserFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.main",
            code=lambda_.Code.from_inline(
                "def main(event, context): "
                "return {'statusCode': 200, 'body': 'CV anonymiser running'}"
            ),
        )

        # API Gateway in front of the Lambda
        api = apigateway.LambdaRestApi(
            self,
            "CvAnonymiserApi",
            handler=cv_lambda,
        )

        # Outputs
        CfnOutput(self, "ApiUrl", value=api.url)
        CfnOutput(self, "LambdaName", value=cv_lambda.function_name)
