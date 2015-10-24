/**
* @package polymerase-driver-aws-apigateway
* @copyright 2015 Andrew Munsell <andrew@wizardapps.net>
*/

import {createCipher} from 'crypto';

import {IAM, KMS, S3} from 'aws-sdk';
import Promise from 'bluebird';
import {AES, HmacSHA256, enc as Encoding} from 'crypto-js';
import extend from 'extend';
import {dependencies} from 'needlepoint';

import BaseDriver from 'polymerase-driver-base';

// Constant used for the "all" region
var ALL_REGIONS = 'all';

export default class AWSAPIGatewayDriver extends BaseDriver {
	/**
	 * Return an array of valid regions
	 */
	static getRegions() {
		return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1'];
	}

	constructor() {
		super();

		// Permutations of stage-region combinations
		this.permutations = [];

		this.aws = {};
	}

	/**
	* Set the service manifest as the context for the driver.
	* @param {object} serviceContext
	*/
	setServiceContext(serviceContext) {
		super.setServiceContext(serviceContext);

		// Create all of the permutations
		this.context.regions.forEach((region) => {
			this.context.stages.forEach((stage) => {
				this.permutations.push({
					region: region,
					stage: stage
				});
			});
		});

		this.aws.iam = new IAM({ region: 'us-east-1' });
		this.aws.kms = new KMS({ region: 'us-east-1' });
		this.aws.s3 = new S3({ region: 'us-east-1' });
	}

	/**
	* Perform all of the required bootstrapping to create a new service. If a
	* service fails to be created, all of the partially created resources
	* should be cleaned up.
	*
	* @return {Promise}
	*/
	createService(service) {
		this.setServiceContext(service);

		return Promise.resolve()
		.then(() => {
			// Create the root level resources for the service
			console.log('aws-apigateway: Creating S3 bucket for ' + service.name);

			return this.createBucket();
		})
		.then(() => {
			// Create the stage specific resources, using all of the configured stages
			// by default.
			return Promise.all(
				this.context.stages.map((stage) => this.createStage(stage))
			);
		})
		.catch((err) => {
			console.error('aws-apigateway: Something went wrong. Cleaning up.');

			// There was a problem creating one or more of the resources, so we
			// actually want to rollback all of the changes
			return this.deleteService()
			.finally(function() {
				throw err;
			});
		});
	}

	/**
	 * Delete all of the resources for the current service
	 */
	deleteService() {
		console.log('aws-apigateway: Deleting the S3 bucket for ' +
			this.context.name);

		return Promise.settle([
			this.deleteBucket(),
			Promise.all(
				this.context.stages.map((stage) => this.deleteStage(stage))
			)
		])
		.map(function(result) {
			if(result.isRejected()) {
				console.log(result.reason().stack);
			}
		});
	}

	/**
	 * Create the specified stage in all of the regions
	 * @param  {string} stage
	 */
	createStage(stage) {
		return Promise.resolve(this.permutations)
		.filter((permutation) => permutation.stage == stage )
		.then((permutations) => {
			console.log('aws-apigateway: Creating KMS encryption keys for ' + stage);

			// Copy the array of permutations so we can add the "all" region to the
			// set of keys that need to be created.
			var keyPermutations = permutations.slice(0);
			keyPermutations.push({
				stage: stage,
				region: ALL_REGIONS
			});

			return this.callWithPermutations(keyPermutations, this.createKey)
				.then(() => {
					console.log('aws-apigateway: Creating Lambda IAM execution roles for ' + stage);

					return this.callWithPermutations(permutations,
						this.createExecutionRole);
				})
				.then(() => {
					console.log('aws-apigateway: Creating IAM policies for the execution role for ' + stage);

					return this.callWithPermutations(permutations,
						this.addPermissionsToExecutionRole);
				});
		});
	}

	/**
	 * Delete the specified stage for the current service, removing all of the
	 * resources associated with it.
	 * @param  {string} stage
	 */
	deleteStage(stage) {
		return Promise.resolve(this.permutations)
		.filter((permutation) => permutation.stage == stage )
		.then((permutations) => {
			// Copy the array of permutations so we can add the "all" region to the
			// set of keys that need to be deleted.
			var keyPermutations = permutations.slice(0);
			keyPermutations.push({
				stage: stage,
				region: ALL_REGIONS
			});

			console.log('aws-apigateway: Deleting IAM policies for the execution role for ' + stage);
			console.log('aws-apigateway: Deleting KMS encryption keys for ' + stage);

			return Promise.settle([
				// Delete the execution role policies, then the execution roles
				// themselves
				this.callWithPermutations(permutations, this.deleteExecutionRolePolicy)
					.then(() => {
						console.log('aws-apigateway: Deleting Lambda execution roles for ' + stage);

						return this.callWithPermutations(permutations, this.deleteExecutionRole)
					}),

				// Remove the KMS keys that were used for encryption
				this.callWithPermutations(keyPermutations, this.deleteKey)
			]);
		});
	}

	/**
	 * Decrypt the specified KMS-encrypted data, returning the response
	 * @param  {string|Buffer} data
	 */
	decryptData(data) {
		return new Promise((resolve, reject) => {
			this.aws.kms.decrypt({
				CiphertextBlob: data
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
	 * Decrypt data locally using the specified key
	 * @param  {string} data
	 * @param  {string} key
	 */
	decryptDataLocally(data, hmac, key) {
		var strKey = (typeof key == 'string') ? key : key.toString('base64');

		// Decrypt the data with the specified key using AES 256
		var decrypted = AES.decrypt(data, strKey);
		var decryptedStr = decrypted.toString(Encoding.Utf8);

		// Verify the HMAC
		var verifyHmac = HmacSHA256(decryptedStr, strKey).toString(Encoding.Hex);

		if(hmac != verifyHmac) {
			throw new Error('aws-apigateway: HMAC validation failed');
		}

		strKey = null;

		return decryptedStr;
	}

	/**
	 * Encrypt the data locally using the specified key and return the AES
	 * encrypted ciphertext as well as the HMAC of the data for verification
	 * purposes.
	 * @param  {string} data
	 * @param  {string} key
	 * @return {object}
	 */
	encryptDataLocally(data, key) {
		var strKey = (typeof key == 'string') ? key : key.toString('base64');

		var encrypted = AES.encrypt(data, strKey).toString();
		var hmac = HmacSHA256(data, strKey).toString(Encoding.Hex);

		data = null;
		strKey = null;

		return {
			data: encrypted,
			hmac: hmac
		};
	}

	/**
	 * Get the object key for the configuration file of the specified stage and
	 * region.
	 * @param  {string} stage
	 * @param  {string} region
	 */
	getConfigObjectKey(stage, region) {
		if(typeof region == 'undefined') {
			return 'config/' + stage + '.json';
		} else {
			return 'config/' + stage + '/' + region + '.json';
		}
	}

	/**
	 * Get the raw configuration objects from S3, including the version
	 * information. For a higher level method that just retrieve the actual
	 * config and decrypts it, see "getConfig" or "getConfigItem"
	 * @param  {string} stage
	 * @param  {string} region
	 */
	getConfigObjects(stage, region, single) {
		if(single === true) {
			var bucketName = this.getBucketName();

			return Promise.resolve()
			.then(() => {
				// Get the encrypted configuration, its HMAC, and the encrypted
				// data key from S3
				return new Promise((resolve, reject) => {
					this.aws.s3.getObject({
						Bucket: bucketName,
						Key: this.getConfigObjectKey(stage, region)
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					})
				});
			})
			.then((obj) => {
				// Parse the S3 object
				obj.Body = JSON.parse(obj.Body.toString('utf8'));

				return obj;
			})
			.then((config) => {
				// Decrypt the data encryption key
				return this.decryptData(new Buffer(config.Body.key, 'base64'))
					.then((key) => {
						key = key.Plaintext;

						// Using the decrypted data encryption key, decrypt the actual
						// configuration object and verify its HMAC
						var decryptedConfig = this.decryptDataLocally(config.Body.data,
							config.Body.hmac, key);

						// Parse the decrypted content
						config.Body.data = JSON.parse(decryptedConfig);

						return config;
					});
			})
			.catch((err) => {
				if(err.code && err.code == 'NoSuchKey') {
					return {
						VersionId: null,
						Body: {
							key: null,
							hmac: null,
							data: {}
						}
					};
				} else {
					throw err;
				}
			});
		} else {
			return Promise.all([
				this.getConfigObjects(stage, ALL_REGIONS, true),
				this.getConfigObjects(stage, region, true)
			]);
		}
	}

	/**
	 * Get all of the configuration data for the current service and stage, and
	 * optionally the specified region.
	 * @param {string} stage
	 * @param {string} region
	 */
	getConfig(stage, region) {
		return this.getConfigObjects(stage, region)
			.spread((stageConfig, regionConfig) => {
				return extend(true, stageConfig.Body.data, regionConfig.Body.data);
			});
	}

	/**
	 * Set the configuration for the current service and stage, and optionally
	 * the specified region.
	 * @param {object} configuration
	 * @param {string} stage
	 * @param {string} region
	 */
	setConfig(configuration, stage, region) {
		// Create a copy of the object to ensure that we do not encrypt the original
		// object that was passed into this function
		var configCopy = extend(true, {}, configuration);

		return Promise.resolve()
			.then(() => {
				// See if we already have a data encryption key, and if not, have KMS
				// generate a new one. If we do have a data encryption key, we need to
				// request it be decrypted so that we can encrypt the actual data itself
				if(configCopy.Body.key == null) {
					return Promise.resolve()
						.then(() => {
							return new Promise((resolve, reject) => {
								this.aws.kms.generateDataKey({
									KeyId: this.getKeyAlias(stage, region),
									KeySpec: 'AES_256'
								}, function(err, data) {
									if(err) {
										reject(err);
									} else {
										resolve(data);
									}
								});
							});
						})
						.then((key) => {
							configCopy.Body.key = key.CiphertextBlob.toString('base64');

							return key.Plaintext.toString('base64');
						});
				} else {
					return this.decryptData(new Buffer(configCopy.Body.key, 'base64'))
						.then((key) => {
							return key.Plaintext;
						});
				}
			})
			.then((dataKey) => {
				// Now we have a decrypted data key, so we can use it to encrypt the
				// data itself.
				if(typeof configCopy.Body.data != 'string') {
					configCopy.Body.data = JSON.stringify(configCopy.Body.data);
				}

				var encryptedParts = this.encryptDataLocally(configCopy.Body.data,
					dataKey);

				configCopy.Body.data = encryptedParts.data;
				configCopy.Body.hmac = encryptedParts.hmac;
			})
			.then(() => {
				return new Promise((resolve, reject) => {
					this.aws.s3.putObject({
						Bucket: this.getBucketName(),
						Key: this.getConfigObjectKey(stage, region),
						Body: JSON.stringify(configCopy.Body, null, 4)
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
		return Promise.resolve()
			.then(() => {
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
			})
			.then(() => {
				return new Promise((resolve, reject) => {
					this.aws.s3.putBucketVersioning({
						Bucket: this.getBucketName(),
						VersioningConfiguration: {
							Status: 'Enabled'
						}
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					})
				});
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
		return Promise.resolve()
			.then(() => {
				return Promise.all([
					new Promise((resolve, reject) => {
						this.aws.kms.describeKey({
							KeyId: this.getKeyAlias(stage, region)
						}, function(err, data) {
							if(err) {
								reject(err);
							} else {
								resolve(data);
							}
						});
					}),

					new Promise((resolve, reject) => {
						this.aws.kms.describeKey({
							KeyId: this.getKeyAlias(stage, ALL_REGIONS)
						}, function(err, data) {
							if(err) {
								reject(err);
							} else {
								resolve(data);
							}
						});
					})
				])
			})
			.spread((key, stageKey) => {
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
									"arn:aws:s3:::" + this.getConfigObjectKey(stage),

									// Allow access to the region's configuration
									"arn:aws:s3:::" + this.getConfigObjectKey(stage, region)
								]
							},

							{
								"Effect": "Allow",
								"Action": [
									"kms:Decrypt",
									"kms:DescribeKey",
									"kms:GetKeyPolicy"
								],
								"Resource": [
									key.KeyMetadata.Arn,
									stageKey.KeyMetadata.Arn
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

	/**
	 * Get the alias for the encryption key for the current service, state, and
	 * region.
	 * @param  {string} stage
	 * @param  {string} region
	 * @return {string}
	 */
	getKeyAlias(stage, region) {
		if(!region) {
			region = ALL_REGIONS;
		}

		return 'alias/' + ['polymerase', this.context.id, stage, region]
			.join('-');
	}

	/**
	 * Create a new master key for the current service, stage, and region.
	 */
	createKey(stage, region) {
		return Promise.resolve()
			.then(() => {
				// Create the actual encryption key itself
				return new Promise((resolve, reject) => {
					this.aws.kms.createKey({
						Description: 'Polymerase key ' + [this.context.id, stage, region]
							.join(', '),
						KeyUsage: 'ENCRYPT_DECRYPT'
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				});
			})
			.then((key) => {
				// Create an alias to the encryption key
				return new Promise((resolve, reject) => {
					this.aws.kms.createAlias({
						AliasName: this.getKeyAlias(stage, region),
						TargetKeyId: key.KeyMetadata.Arn
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(key);
						}
					});
				});
			});
	}

	/**
	 * Schedule the deletion of the key for the current service, stage, and region
	 * @param  {string} stage
	 * @param  {string} region
	 */
	deleteKey(stage, region) {
		return Promise.resolve()
			.then(() => {
				return new Promise((resolve, reject) => {
					this.aws.kms.describeKey({
						KeyId: this.getKeyAlias(stage, region)
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				});
			})
			.then((key) => {
				return new Promise((resolve, reject) => {
					this.aws.kms.scheduleKeyDeletion({
						KeyId: key.KeyMetadata.Arn,
						PendingWindowInDays: 7
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
}
