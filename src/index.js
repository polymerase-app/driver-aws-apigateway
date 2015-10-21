/**
* @package polymerase-driver-aws-apigateway
* @copyright 2015 Andrew Munsell <andrew@wizardapps.net>
*/

import {IAM, Lambda, S3} from 'aws-sdk';
import {Promise} from 'bluebird';
import {dependencies} from 'needlepoint';

export default class AWSAPIGatewayDriver {
	constructor() {
		// Permutations of stage-region combinations
		this.permutations = [];

		this.aws = {};

		this.executionRole = null;
	}

	/**
	* Set the service manifest as the context for the driver.
	* @param {object} serviceContext
	*/
	setServiceContext(serviceContext) {
		this.context = serviceContext;

		// Create all of the permutations
		this.context.regions.forEach((region) => {
			this.context.stages.all.forEach((stage) => {
				this.permutations.push({
					region: region,
					stage: stage
				});
			});
		});

		this.aws.iam = new IAM({ region: 'us-east-1' });
		this.aws.s3 = new S3({ region: 'us-east-1' });
	}

	/**
	* Perform all of the required bootstrapping to create a new service. If a
	* service fails to be created, all of the partially created resources
	* should be cleaned up.
	*
	* @return {Promise}
	*/
	createService() {
		return Promise.resolve()
		.then(() => {
			// Create the root level resources for the service
			console.log('aws-apigateway: Creating S3 bucket');

			return this.createBucket();
		})
		.then(() => {
			// Create the stage specific resources, using all of the configured stages
			// by default.
			return Promise.all(this.context.stages.all.map((stage) => {
				return this.createStage(stage);
			}));
		})
		.then(function() {
			throw new Error('Dummyerr');
		})
		.catch((err) => {
			console.error('aws-apigateway: Something went wrong. Cleaning up.');

			// There was a problem creating one or more of the resources, so we
			// actually want to rollback all of the changes
			return Promise.settle([
				this.deleteBucket(),
				this.callWithAllPermutations(this.deleteExecutionRolePolicy)
					.then(() => {
						return this.callWithAllPermutations(this.deleteExecutionRole)
					})
			])
			.map(function(result) {
				if(result.isRejected()) {
					console.log(result.reason().stack);
				}
			})
			.finally(function() {
				throw err;
			});
		});
	}

	/**
	 * Create the specified stage in all of the regions
	 * @param  {string} stage
	 */
	createStage(stage) {
		return Promise.resolve(this.permutations)
		.filter((permutation) => {
			return permutation.stage == stage;
		})
		.then((permutations) => {
			console.log('aws-apigateway: Creating Lambda IAM execution role');

			return this.callWithPermutations(permutations,
				this.createExecutionRole)
				.then(() => {
					console.log('aws-apigateway: Creating IAM policies for the execution role');

					return this.callWithPermutations(permutations,
						this.addPermissionsToExecutionRole);
				});
		});
	}

	/**
	 * Call the specified method with the defined stage/region permutations
	 * @param {array}    permutations
	 * @param {function} func
	 */
	callWithPermutations(permutations, func) {
		return Promise.all(permutations.map((combination) => {
			return func.call(this, combination.stage, combination.region);
		}));
	}

	/**
	 * Call the specified function with all of the current stage/region
	 * permutations. Most useful for cleanup.
	 * @param  {function} func
	 */
	callWithAllPermutations(func) {
		return this.callWithPermutations(this.permutations, func);
	}

	/**
	 * Get the name of the bucket for the current service
	 * @return {string}
	 */
	getBucketName() {
		return ['polymerase', this.context.id].join('-');
	}

	/**
	 * Create the S3 bucket for the current service
	 */
	createBucket() {
		return new Promise((resolve, reject) => {
			this.aws.s3.createBucket({
				Bucket: this.getBucketName()
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(data);
				}
			})
		});
	}

	/**
	 * Delete the S3 bucket for the current service
	 */
	deleteBucket() {
		return new Promise((resolve, reject) => {
			this.aws.s3.deleteBucket({
				Bucket: this.getBucketName()
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(data);
				}
			})
		});
	}

	/**
	 * Get the name of the execution role on AWS from the specified stage and
	 * region.
	 *
	 * @return {string}
	 */
	getExecutionRoleName(stage, region) {
		return ['polymerase', this.context.id, region, stage, 'lambda', 'exec']
			.join('-');
	}

	/**
	 * Create the execution role
	 * @return {Promise}
	 */
	createExecutionRole(stage, region) {
		// Create a new execution role that will be used by the Lambda
		// functions when executing. This is the role we will add permissions
		// for to decrypt data and access other AWS resources
		return new Promise((resolve, reject) => {
			this.aws.iam.createRole({
				AssumeRolePolicyDocument: JSON.stringify({
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Principal": {
								"Service": ["lambda.amazonaws.com"]
							},
							"Action": ["sts:AssumeRole"]
						}
					]
				}, null, 4),
				RoleName: this.getExecutionRoleName(stage, region)
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(data);
				}
			});
		});
	}

	/**
	 * Delete the execution role for the current service
	 * @return {Promise}
	 */
	deleteExecutionRole(stage, region) {
		return new Promise((resolve, reject) => {
			this.aws.iam.deleteRole({
				RoleName: this.getExecutionRoleName(stage, region)
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(data);
				}
			});
		});
	}

	/**
	 * Add the required IAM permissions to the execution role for the current
	 * service, stage, and region
	 * @param {string} stage
	 * @param {string} region
	 */
	addPermissionsToExecutionRole(stage, region) {
		return this.createExecutionRolePolicy(stage, region)
			.then((policy) => {
				return new Promise((resolve, reject) => {
					this.aws.iam.attachRolePolicy({
						PolicyArn: policy.Policy.Arn,
						RoleName: this.getExecutionRoleName(stage, region)
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				});
			});
	}

	/**
	 * Get the execution role policy name for the current service, stage, and
	 * region.
	 * @param  {string} stage
	 * @param  {string} region
	 */
	getExecutionRolePolicyName(stage, region) {
		return ['polymerase', this.context.id, stage, region, 'lambda', 'exec']
			.join('-');
	}

	/**
	 * Create the execution role policy that will be attached to the Lambda
	 * execution role.
	 * @param  {string} stage
	 * @param  {string} region
	 */
	createExecutionRolePolicy(stage, region) {
		return new Promise((resolve, reject) => {
			var policyDocument = JSON.stringify({
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": [
							"s3:GetObject"
						],
						"Resource": [
							// Allow access to the stage configuration
							"arn:aws:s3:::" + this.getBucketName() + "/config/" + stage + ".json",

							// Allow access to the region's configuration
							"arn:aws:s3:::" + this.getBucketName() + "/config/" + stage + "/" + region + ".json"
						]
					}
				]
			}, null, 4);

			this.aws.iam.createPolicy({
				PolicyName: this.getExecutionRolePolicyName(stage, region),
				PolicyDocument: policyDocument
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(data);
				}
			});
		});
	}

	/**
	 * Delete the execution role policy that should be attached to the Lambda
	 * execution role.
	 * @param  {string} stage
	 * @param  {string} region
	 */
	deleteExecutionRolePolicy(stage, region) {
		return this._findPolicy(this.getExecutionRolePolicyName(stage, region))
			.then((policy) => {
				return new Promise((resolve, reject) => {
					this.aws.iam.detachRolePolicy({
						PolicyArn: policy.Arn,
						RoleName: this.getExecutionRoleName(stage, region)
					}, function(err, data) {
						resolve(policy);
					});
				});
			})
			.then((policy) => {
				return new Promise((resolve, reject) => {
					this.aws.iam.deletePolicy({
						PolicyArn: policy.Arn
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				});
			});
	}

	/**
	 * Find the policy with the specified name. Used as a helper to find the ARN
	 * of the policy.
	 * @param  {string} policyName
	 */
	_findPolicy(policyName, marker) {
		return new Promise((resolve, reject) => {
			var params = {
				Scope: 'Local',
				MaxItems: 100
			};

			if(marker) {
				params.Marker = marker;
			}

			this.aws.iam.listPolicies(params, (err, data) => {
				if(err) {
					reject(err);
				} else {
					var matchedPolicy = data.Policies
						.filter(function(policy) {
							return policy.PolicyName == policyName;
						});

					if(matchedPolicy.length > 0) {
						resolve(matchedPolicy[0]);
					} else if (data.IsTruncated) {
						this._findPolicy(policyName, Marker)
							.then(resolve)
							.catch(reject);
					} else {
						reject(new Error('The policy ' + policyName + ' was not found'));
					}
				}
			});
		});
	}
}
