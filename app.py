#!/usr/bin/env python3
import aws_cdk as cdk

from cv_anonymiser.cv_anonymiser_stack import CvAnonymiserStack


app = cdk.App()
CvAnonymiserStack(app, "CvAnonymiserStack",
    # If you don't specify 'env', this stack will be environment-agnostic.
    # Account/Region-dependent features and context lookups will not work,
    # but a single synthesized template can be deployed anywhere.

    # Uncomment the next line to specialize this stack for the AWS Account
    # and Region that are implied by the current CLI configuration.

    # Uncomment the next line if you know exactly what Account and Region you
    # want to deploy the stack to. */

    env=cdk.Environment(account='460742884922', region='eu-west-2'),

    # For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
    )

app.synth()
