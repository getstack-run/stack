import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// AWS general APIs — Lambda, IAM, EC2, SNS, SQS, DynamoDB. Each AWS
// service has its own host pattern and API style:
//   Lambda REST: lambda.{region}.amazonaws.com/2015-03-31/functions/{name}/…
//   IAM Query:   iam.amazonaws.com/?Action=…   (POST body or query string)
//   EC2 Query:   ec2.{region}.amazonaws.com/?Action=…
//   SNS Query:   sns.{region}.amazonaws.com/?Action=Publish
//   SQS Query:   sqs.{region}.amazonaws.com/{account}/{queue} with Action=
//   DynamoDB:    dynamodb.{region}.amazonaws.com  (JSON body, X-Amz-Target
//                header selects operation)
// Where Action= is carried in the query string or POST body, we bind on
// the body.Action field; callers using JSON APIs (DynamoDB) bind on the
// X-Amz-Target header via headers.x-amz-target.

export const awsIntents = [
  defineIntent({
    name: 'aws.lambda_invoke',
    effect: 'write',
    description:
      'Invoke a Lambda function synchronously or asynchronously. Binds POST lambda.{region}.amazonaws.com/2015-03-31/functions/{name}/invocations.',
    params: z.object({ function_name: z.string().min(1).max(170).optional() }),
    expand: ({ function_name }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^lambda\\.[^.]+\\.amazonaws\\.com$' },
      {
        path: 'url.pathname',
        op: 'matches',
        value: function_name
          ? `^/2015-03-31/functions/${function_name.replace(/[.+*?^${}()|[\]\\]/g, '\\$&')}/invocations$`
          : '^/2015-03-31/functions/[^/]+/invocations$',
      },
    ],
  }),

  defineIntent({
    name: 'aws.lambda_create_function',
    effect: 'write',
    description:
      'Create a new Lambda function. Binds POST lambda.{region}.amazonaws.com/2015-03-31/functions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^lambda\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'url.pathname', op: 'eq', value: '/2015-03-31/functions' },
    ],
  }),

  defineIntent({
    name: 'aws.lambda_update_function_code',
    effect: 'write',
    description:
      'Update the deployment package of an existing Lambda function. Binds PUT lambda.{region}.amazonaws.com/2015-03-31/functions/{name}/code.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.host', op: 'matches', value: '^lambda\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'url.pathname', op: 'matches', value: '^/2015-03-31/functions/[^/]+/code$' },
    ],
  }),

  defineIntent({
    name: 'aws.lambda_list_functions',
    effect: 'read',
    description:
      'List Lambda functions in the region. Binds GET lambda.{region}.amazonaws.com/2015-03-31/functions.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'matches', value: '^lambda\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'url.pathname', op: 'eq', value: '/2015-03-31/functions' },
    ],
  }),

  defineIntent({
    name: 'aws.lambda_delete_function',
    effect: 'destructive',
    description:
      'Delete a Lambda function. Binds DELETE lambda.{region}.amazonaws.com/2015-03-31/functions/{name}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.host', op: 'matches', value: '^lambda\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'url.pathname', op: 'matches', value: '^/2015-03-31/functions/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'aws.iam_create_role',
    effect: 'write',
    description:
      'Create an IAM role. Binds POST iam.amazonaws.com with Action=CreateRole. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'iam.amazonaws.com' },
      { path: 'body.Action', op: 'eq', value: 'CreateRole' },
    ],
  }),

  defineIntent({
    name: 'aws.iam_attach_role_policy',
    effect: 'write',
    description:
      'Attach a managed policy to an IAM role. Binds POST iam.amazonaws.com with Action=AttachRolePolicy. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'iam.amazonaws.com' },
      { path: 'body.Action', op: 'eq', value: 'AttachRolePolicy' },
    ],
  }),

  defineIntent({
    name: 'aws.iam_list_users',
    effect: 'read',
    description:
      'List IAM users on the account. Binds POST iam.amazonaws.com with Action=ListUsers.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'iam.amazonaws.com' },
      { path: 'body.Action', op: 'eq', value: 'ListUsers' },
    ],
  }),

  defineIntent({
    name: 'aws.ec2_run_instances',
    effect: 'write',
    description:
      'Launch one or more EC2 instances. Binds POST ec2.{region}.amazonaws.com with Action=RunInstances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^ec2\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'RunInstances' },
    ],
  }),

  defineIntent({
    name: 'aws.ec2_terminate_instances',
    effect: 'destructive',
    description:
      'Terminate EC2 instances. Binds POST ec2.{region}.amazonaws.com with Action=TerminateInstances. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^ec2\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'TerminateInstances' },
    ],
  }),

  defineIntent({
    name: 'aws.ec2_describe_instances',
    effect: 'read',
    description:
      'Describe EC2 instances in the region. Binds POST ec2.{region}.amazonaws.com with Action=DescribeInstances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^ec2\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'DescribeInstances' },
    ],
  }),

  defineIntent({
    name: 'aws.ec2_start_instances',
    effect: 'write',
    description:
      'Start stopped EC2 instances. Binds POST ec2.{region}.amazonaws.com with Action=StartInstances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^ec2\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'StartInstances' },
    ],
  }),

  defineIntent({
    name: 'aws.ec2_stop_instances',
    effect: 'write',
    description:
      'Stop running EC2 instances. Binds POST ec2.{region}.amazonaws.com with Action=StopInstances.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^ec2\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'StopInstances' },
    ],
  }),

  defineIntent({
    name: 'aws.sns_publish',
    effect: 'send',
    recipient_paths: ['body.TopicArn', 'body.TargetArn', 'body.PhoneNumber'],
    description:
      'Publish a message to an SNS topic. Binds POST sns.{region}.amazonaws.com with Action=Publish.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^sns\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'body.Action', op: 'eq', value: 'Publish' },
    ],
  }),

  defineIntent({
    name: 'aws.sqs_send_message',
    effect: 'write',
    description:
      'Send a message to an SQS queue. Binds POST sqs.{region}.amazonaws.com with Action=SendMessage.',
    params: z.object({ queue_url_prefix: z.string().max(512).optional() }),
    expand: ({ queue_url_prefix }) => {
      const base: Constraint[] = [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'matches', value: '^sqs\\.[^.]+\\.amazonaws\\.com$' },
        { path: 'body.Action', op: 'eq', value: 'SendMessage' },
      ];
      if (queue_url_prefix) {
        base.push({ path: 'url.pathname', op: 'starts_with', value: queue_url_prefix });
      }
      return base;
    },
  }),

  defineIntent({
    name: 'aws.sqs_receive_message',
    effect: 'write',
    description:
      'Receive messages from an SQS queue. Binds POST sqs.{region}.amazonaws.com with Action=ReceiveMessage.',
    params: z.object({ queue_url_prefix: z.string().max(512).optional() }),
    expand: ({ queue_url_prefix }) => {
      const base: Constraint[] = [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.host', op: 'matches', value: '^sqs\\.[^.]+\\.amazonaws\\.com$' },
        { path: 'body.Action', op: 'eq', value: 'ReceiveMessage' },
      ];
      if (queue_url_prefix) {
        base.push({ path: 'url.pathname', op: 'starts_with', value: queue_url_prefix });
      }
      return base;
    },
  }),

  defineIntent({
    name: 'aws.dynamodb_put_item',
    effect: 'write',
    description:
      'Put an item into a DynamoDB table. Binds POST dynamodb.{region}.amazonaws.com with X-Amz-Target DynamoDB_20120810.PutItem.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^dynamodb\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'headers.x-amz-target', op: 'eq', value: 'DynamoDB_20120810.PutItem' },
    ],
  }),

  defineIntent({
    name: 'aws.dynamodb_get_item',
    effect: 'read',
    description:
      'Read an item from a DynamoDB table. Binds POST dynamodb.{region}.amazonaws.com with X-Amz-Target DynamoDB_20120810.GetItem.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^dynamodb\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'headers.x-amz-target', op: 'eq', value: 'DynamoDB_20120810.GetItem' },
    ],
  }),

  defineIntent({
    name: 'aws.dynamodb_query',
    effect: 'read',
    description:
      'Query items from a DynamoDB table using a key condition. Binds POST dynamodb.{region}.amazonaws.com with X-Amz-Target DynamoDB_20120810.Query.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^dynamodb\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'headers.x-amz-target', op: 'eq', value: 'DynamoDB_20120810.Query' },
    ],
  }),

  defineIntent({
    name: 'aws.dynamodb_scan',
    effect: 'read',
    description:
      'Scan a DynamoDB table end-to-end. Binds POST dynamodb.{region}.amazonaws.com with X-Amz-Target DynamoDB_20120810.Scan.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^dynamodb\\.[^.]+\\.amazonaws\\.com$' },
      { path: 'headers.x-amz-target', op: 'eq', value: 'DynamoDB_20120810.Scan' },
    ],
  }),
];
