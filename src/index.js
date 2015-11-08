/**
* @package polymerase-driver-aws-apigateway
* @copyright 2015 Andrew Munsell <andrew@wizardapps.net>
*/

import {exec, spawn} from 'child_process';
import {createCipher} from 'crypto';
import {readFileSync, statSync, writeFileSync} from 'fs';
import {tmpdir} from 'os';
import {join, sep as pathSeparator} from 'path';

import AdmZip from 'adm-zip';
import {CloudFormation, IAM, KMS, S3} from 'aws-sdk';
import Promise from 'bluebird';
import {pascalCase} from 'change-case';
import {AES, HmacSHA256, enc as Encoding} from 'crypto-js';
import extend from 'extend';
import {sync as mkpath} from 'mkpath';
import moment from 'moment';
import {render as mustache} from 'mustache';
import {dependencies} from 'needlepoint';
import {v4 as uuid} from 'node-uuid';

import BaseDriver from 'polymerase-driver-base';

// Constant used for the "all" region
const ALL_REGIONS = 'all';

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

		// Promises representing ongoing "wait for stack" calls. Used to allow for
		// re-using a single wait loop instead of performing multiple API calls.
		this._stackWait = {};
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

		this.aws.cloudFormation = new CloudFormation({ region: 'us-east-1' });
		this.aws.iam = new IAM({ region: 'us-east-1' });
		this.aws.kms = new KMS({ region: 'us-east-1' });
		this.aws.s3 = new S3({ region: 'us-east-1' });
	}

	/**
	 * Get the name of the CloudFormation stack used for the service's resources
	 * @return {string}
	 */
	getServiceStackName() {
		return ['polymerase', this.context.name, this.context.id].join('-');
	}

	/**
	 * Get the resource ID for the substack used for stage-region resource creation.
	 * @param stage
	 * @param region
	 * @returns {string}
	 */
	getServiceResourceName(stage, region) {
		return pascalCase([this.context.id, stage, region, 'resources'].join('-'))
				.replace(/_/g, '');
	}

	/**
	 * Get an output for the service stack with the following key
	 * @param  {string} key
	 */
	getServiceStackOutput(key) {
		return this.waitForStackReady(this.getServiceStackName())
			.then((stack) => {
				var output = stack.Outputs
					.filter((output) => output.OutputKey == key);

				if(output.length < 1) {
					throw new Error('The specified output does not exist.');
				} else {
					return output[0].OutputValue;
				}
			});
	}

	/**
	 * Get the template for the specified stack name or ID
	 * @param  {string} id
	 */
	getStackTemplate(id) {
		return new Promise((resolve, reject) => {
			this.aws.cloudFormation.getTemplate({
				StackName: id
			}, function(err, data) {
				if(err) {
					reject(err);
				} else {
					resolve(JSON.parse(data.TemplateBody));
				}
			});
		});
	}

	/**
	 * Get the ARN of a resource from the specified stack
	 * @param stack
	 * @param resource
	 */
	getResourceArnFromStack(stack, resource) {
		return new Promise((resolve, reject) => {
			this.aws.cloudFormation.describeStackResource({
				StackName: stack,
				LogicalResourceId: resource
			}, function(err, result) {
				if(err) {
					reject(err);
				} else {
					resolve(result.StackResourceDetail.PhysicalResourceId);
				}
			});
		});
	}

	/**
	 * Get the stack ARN for the resource CloudFormation stack for the specified stage and region
	 * @param stage
	 * @param region
	 */
	getResourceStackArn(stage, region) {
		return this.getResourceArnFromStack(this.getServiceStackName(),
				this.getServiceResourceName(stage, region));
	}

	/**
	 * Get an ARN for a resource from the stage-region CloudFormation sub-stack
	 * @param stage
	 * @param region
	 * @param resource
	 * @returns {Promise.<String>}
	 */
	getArnFromResourceStack(stage, region, resource) {
		return this.getResourceStackArn(stage, region)
			.then((arn) => {
				return this.getResourceArnFromStack(arn, resource);
			});
	}

	/**
	 * Update the stack template for the given CloudFormation stack
	 * @param  {string} id
	 * @param  {object} template
	 */
	updateStackTemplate(id, template) {
		var params = [];

		if(typeof template.Parameters == 'object' && !template.Parameters.length) {
			params = Object.keys(template.Parameters);
			params = params.map(function(param) {
				return {
					ParameterKey: param,
					UsePreviousValue: true
				};
			});
		}

		return new Promise((resolve, reject) => {
			this.aws.cloudFormation.updateStack({
				StackName: id,
				Capabilities: ['CAPABILITY_IAM'],
				Parameters: params,
				TemplateBody: JSON.stringify(template, null, 4)
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
	 * Wait for the stack with the specified ID to be ready
	 * @param  {String} id
	 */
	waitForStackReady(id, noReuse) {
		if(this._stackWait.hasOwnProperty(id) && noReuse !== true) {
			return this._stackWait[id];
		}

		var promise = new Promise((resolve, reject) => {
			console.log('aws-apigateway: Waiting for CloudFormation...');

			this.aws.cloudFormation.describeStacks({
				StackName: id
			}, (err, data) => {
				if(err) {
					delete this._stackWait[id];

					reject(err);
				} else {
					var stack = data.Stacks[0];

					switch(stack.StackStatus) {
						case 'CREATE_COMPLETE':
						case 'UPDATE_COMPLETE':
						case 'ROLLBACK_COMPLETE':
						case 'UPDATE_ROLLBACK_COMPLETE':
							console.log('aws-apigateway: CloudFormation stack ready');
							delete this._stackWait[id];

							return resolve(stack);
					}

					setTimeout(() => {
						resolve(this.waitForStackReady(id, true));
					}, 7500);
				}
			});
		});

		this._stackWait[id] = promise;

		return promise;
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
			console.log('aws-apigateway: Creating service-level resources');

			var rootResourceTemplate = readFileSync(join(__dirname, '..',
				'cloud-formation', 'resources.json'), 'utf8');

			return new Promise((resolve, reject) => {
				this.aws.cloudFormation.createStack({
					StackName: this.getServiceStackName(),
					Capabilities: [
						'CAPABILITY_IAM'
					],
					OnFailure: 'DELETE',
					TemplateBody: rootResourceTemplate
				}, function(err, data) {
					if(err) {
						reject(err);
					} else {
						resolve(data);
					}
				});
			});
		})
		.then((stack) => {
			// Wait for the stack to finish being created
			return Promise.all([
				this.waitForStackReady(this.getServiceStackName()),
				this.getServiceStackOutput('BucketName')
			]);
		})
		.spread((stack, bucketName) => {
			// Now, upload the stage/region CloudFormation templates to the S3 bucket
			// to be used to create the stages/regions.
			var stageRegionResourcesTemplate = readFileSync(join(__dirname, '..',
				'cloud-formation', 'stage-region-resources.json'));

			return Promise.all([
				stack,

				bucketName,

				new Promise((resolve, reject) => {
					this.aws.cloudFormation.getTemplate({
						StackName: stack.StackName
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				}),

				new Promise((resolve, reject) => {
					this.aws.s3.putObject({
						Bucket: bucketName,
						Key: 'templates/stage-region-resources.json',
						Body: stageRegionResourcesTemplate
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				})
			]);
		})
		.spread((stack, bucketName, stackTemplate, resourceTemplate) => {
			stackTemplate = JSON.parse(stackTemplate.TemplateBody);

			return Promise.all(
				this.context.stages.map((stage) => this.createStage(stage))
			);
		})
		.then((stack) => {
			// Wait for the stack to finish being updated with the new stage
			// sub-stacks
			return this.waitForStackReady(stack.StackId);
		})
		.catch((err) => {
			console.error('aws-apigateway: Something went wrong. Cleaning up.');
			console.log(err.stack);

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
        console.log('aws-apigateway: Deleting all the stages for the service.');

		return Promise.all(this.context.stages.map((stage) => this.deleteStage(stage)))
			.then(() => {
                console.log('aws-apigateway: Emptying the S3 bucket for ' +
        			this.context.name);

				return this.emptyServiceBucket();
			})
			.then(() => {
				return this.waitForStackReady(this.getServiceStackName());
			})
			.then(() => {
				console.log('aws-apigateway: Deleting all CloudFormation stacks');

				return new Promise((resolve, reject) => {
					this.aws.cloudFormation.deleteStack({
						StackName: this.getServiceStackName()
					}, function(err, data) {
						if(err) {
							reject(err);
						} else {
							resolve(data);
						}
					});
				});
			})
			.then(() => {
				return this.waitForStackReady(this.getServiceStackName())
					.catch((err) => {
						// We want to ignore the error since it's just CloudFormation just
						// responding saying that the stack doesn't exist anymore.
					});
			});
	}

    /**
     * Initialize the service using the specified configuration and at the
     * specified path
     * @param  {object} config
     * @param  {string} path
     */
    initializeService(config, path) {
        var markerPath = join(path, '.polymerase-init');

        try {
            var markerStat = statSync(markerPath);

            // If the stat call succeeded, then the initialization marker
            // already exists, so we can simply exit.
            return;
        } catch(e) {}

        // Ensure the subfolders are initialized and have been created
        mkpath(join(path, 'src/routes'));
        mkpath(join(path, 'src/lib'));

        mkpath(join(path, 'test/routes'));
        mkpath(join(path, 'test/lib'));

        // Install the .gitignore file if one does not exist yet
        var gitIgnorePath = join(path, '.gitignore');

        try {
            statSync(gitIgnorePath);
        } catch(e) {
            var gitIgnoreTemplate = readFileSync(join(__dirname, '..',
                'templates', '_gitignore'));

            writeFileSync(gitIgnorePath, gitIgnoreTemplate, {
                encoding: 'utf8',
                flag: 'w'
            });
        }

        var packageJsonPath = join(path, 'package.json');
        try {
            statSync(packageJsonPath);
        } catch(e) {
			var packageJsonTemplate = readFileSync(join(__dirname, '..', 'templates',
					'package.json'));

			packageJsonTemplate.name = config.name;
			packageJsonTemplate.version = config.version;

            // The package.json file likely doesn't exist, so we can try and
            // create it now.
            writeFileSync(packageJsonPath, JSON.stringify(packageJsonTemplate, null, 4), {
                encoding: 'utf8',
                flag: 'w'
            });
        }

		var polymeraseJsPath = join(path, 'index.js');
		try {
			statSync(polymeraseJsPath);
		} catch(e) {
			var polymeraseJsTemplate = readFileSync(join(__dirname, '..', 'templates',
					'polymerase.js'));

			var polymeraseJsContents = mustache(polymeraseJsTemplate, {
				year: moment().format('YYYY'),
				service: this.context
			});

			writeFileSync(packageJsonPath, polymeraseJsContents, {
				encoding: 'utf8',
				flag: 'w'
			});
		}

        // Run NPM install
        console.log('aws-apigateway: Installing required NPM modules');

        return Promise.resolve()
            .then(() => {
				return new Promise((resolve, reject) => {
					exec('npm install', {
						cwd: folder
					}, function(err, stdout, stderr) {
						if(err) {
							console.log('aws-apigateway: The npm install command failed')

							resolve(false);
						} else {
							resolve();
						}
					});
				});
            })
            .then(() => {
                // Add the marker to indicate the service was initialized on
                // this particular machine
                writeFileSync(join(path, '.polymerase-init'), '', {
                    encoding: 'utf8',
                    flag: 'w'
                });
            });
    }

	/**
	 * Create a stage for the current service
	 * @param  {string} stage Name of the stage to create
	 * @return {Promise}
	 */
	createStage(stage) {
		return this.waitForStackReady(this.getServiceStackName())
			.then((stack) => {
				// We know the stack is ready to be modified, so now we can go ahead
				// and get the current stack template to prepare it to be modified
				return Promise.all([
					stack,
					this.getStackTemplate(stack.StackName),
					this.getServiceStackOutput('BucketName'),
					this.createKey(stage, ALL_REGIONS)
				]);
			})
			.spread((stack, stackTemplate, bucketName, stageKey) => {
				// Modify the template to add the new resources (i.e. the sub stack
				// definitions)
				return Promise.resolve(this.context.regions)
					.map((region) => {
						return this.createKey(stage, region)
							.then((regionKey) => {
								return {
									region: region,
									key: regionKey
								};
							});
					})
					.map((region) => {
						var resourceKey = this.getResourceStackArn(stage, region.region);

						stackTemplate.Resources[resourceKey] = {
							Type: 'AWS::CloudFormation::Stack',
							Properties: {
								TemplateURL: 'https://s3.amazonaws.com/' + bucketName
									+ '/templates/stage-region-resources.json',

								Parameters: {
									PolymeraseBucket: bucketName,
									PolymeraseStage: stage,
									PolymeraseRegion: region.region,
									PolymeraseKMSStageKey: stageKey.KeyMetadata.Arn,
									PolymeraseKMSRegionKey: region.key.KeyMetadata.Arn,
								}
							}
						};
					})
					.then(() => {
						return Promise.all([
							stack,
							stackTemplate
						]);
					});
			})
			.spread((stack, stackTemplate) => {
				// Update the stack template
				return this.updateStackTemplate(stack.StackId, stackTemplate);
			})
			.then((stack) => {
				return this.waitForStackReady(stack.StackId);
			});
	}

	/**
	 * Delete the specified stage from the current service
	 * @param  {string} stage
	 */
	deleteStage(stage) {
		return this.waitForStackReady(this.getServiceStackName())
			.then((stack) => {
				// We know the stack is ready to be modified, so now we can go ahead
				// and get the current stack template to prepare it to be modified
				return Promise.all([
					stack,
					this.getStackTemplate(stack.StackName),
					this.getServiceStackOutput('BucketName'),
					this.deleteKey(stage, ALL_REGIONS)
				]);
			})
			.spread((stack, stackTemplate, bucketName, stageKey) => {
				// Modify the template to remove the resources (i.e. the sub stack
				// definitions)
				return Promise.resolve(this.context.regions)
					.map((region) => {
						return this.deleteKey(stage, region)
							.then(() => {
								return region;
							});
					})
					.map((region) => {
						var resourceKey = this.getResourceStackArn(stage, region);

						delete stackTemplate.Resources[resourceKey];
					})
					.then(() => {
						return Promise.all([
							stack,
							stackTemplate
						]);
					});
			})
			.spread((stack, stackTemplate) => {
				// Update the stack template
				return this.updateStackTemplate(stack.StackId, stackTemplate);
			})
			.then((stack) => {
				return this.waitForStackReady(stack.StackId);
			});
	}

	/**
	 * Initialize a route in the specified local folder, using the specified route path and options.
	 * The initial skeleton for the route will be placed in the folder. Remote resources will
	 * not be created at this point-- they will only be created once the route is deployed to a
	 * stage.
	 * @param folder
	 * @param path
	 * @param options
	 */
	initializeRoute(folder, path, options) {
		// Get the path to the route folder
		var routePath = join(folder, 'src', 'routes', this.getRouteFolderForPath(path));
		mkpath(routePath);

		// We can create the folder for the method
		var methodPath = join(routePath, '__' + options.method.toLowerCase());
		mkpath(methodPath);

		// Ensure that the configuration file doesn't already exist so we do not overwrite it
		try {
			statSync(join(methodPath, 'polymerase.json'));

			return false;
		} catch(e) {}

		// Populate it with the default JSON options for the method
		var polymeraseRouteJsonTemplate = JSON.parse(readFileSync(join(__dirname, '..', 'templates',
				'routes', 'polymerase-route.json')));

		polymeraseRouteJsonTemplate.id = uuid();
		polymeraseRouteJsonTemplate.paths.push(path);

		// Assign the resource limits if they were specified
		if(options.resources) {
			if(options.resources.memory) {
				polymeraseRouteJsonTemplate.parameters['aws-apigateway'].resources.memory =
						options.resources.memory;
			}

			if(options.resources.timeout) {
				polymeraseRouteJsonTemplate.parameters['aws-apigateway'].resources.timeout =
						options.resources.timeout;
			}
		}

		// Now, write the configuration to the new route folder
		writeFileSync(join(methodPath, 'polymerase-route.json'),
				JSON.stringify(polymeraseRouteJsonTemplate, null, 4), {
					encoding: 'utf8',
					flag: 'w'
				}
		);

		// Write the template JS file for the entry-point of the route handler.
		var handlerTemplate = readFileSync(join(__dirname, '..', 'templates', 'routes', 'index.js'),
				{
					encoding: 'utf8'
				}
		);

		var handlerContents = mustache(handlerTemplate, {
			year: moment().format('YYYY'),
			service: this.context,

			method: options.method,
			path: path
		});

		writeFileSync(join(methodPath, 'index.js'), handlerContents, {
			encoding: 'utf8',
			flag: 'w'
		});

		return true;
	}

	/**

	 * Package the code for the route. The promise returned resolves to a buffer containing the
	 * contents of the ZIP that houses the route.
	 * @param folder
	 * @param path
	 */
	packageRoute(folder, path) {
		return Promise.resolve()
			.then(() => {
				console.log('aws-apigateway: Ensuring NPM dependencies have been installed');

				return new Promise((resolve, reject) => {
					exec('npm install', {
						cwd: folder
					}, function(err, stdout, stderr) {
						if(err) {
							reject(err);
						} else {
							resolve();
						}
					});
				});
			})
			.then(() => {
				console.log('aws-apigateway: Packaging route');

				var routePath = this.getRouteFolderForPath(path);
				var routeFolder = join(folder, 'src/routes', routePath);

				var zip = new AdmZip();

				zip.addLocalFolder(join(folder, 'node_modules'), 'node_modules');

				zip.addLocalFile(join(folder, 'index.js'), '.');
				zip.addLocalFolder(join(folder, 'src', 'lib'), 'src/lib');
				zip.addLocalFolder(routeFolder, 'src/routes/' + routePath);

				return new Promise((resolve, reject) => {
					zip.toBuffer(function(buff) {
						resolve(buff);
					}, function(err) {
						reject(err);
					})
				});
			});
	}

	/**
	 * Upload the code for the route to S3. The promise returned resolves to the S3 bucket, URL,
	 * and version for the uploaded ZIP file.
	 * @param path
	 * @param zip Buffer containing the contents of the ZIP
	 */
	uploadRoute(path, zip) {
		return this.getServiceStackOutput('BucketName')
			.then((bucket) => {
				var routePath = this.getRouteFolderForPath(path);
				var key = 'packages/routes/' + routePath + '.zip';

				return new Promise((resolve, reject) => {
					this.aws.s3.putObject({
						Bucket: bucket,
						Key: key,
						Body: zip,
						ContentType: 'application/zip',
						ServerSideEncryption: 'AES256'
					}, function(err, result) {
						if(err) {
							reject(err);
						} else {
							result.Bucket = bucket;
							result.Key = key;

							resolve(result);
						}
					})
				});
			});
	}

	/**
	 * Get the folder name for the specified API path
	 * @param path
	 */
	getRouteFolderForPath(path) {
		path = path.replace(/^\//, '');
		path = path.replace(/\/$/, '');
		path = path.replace(/\{([a-z\d\-\_]+)\}/ig, '_$1_');
		path = path.split('/');

		return join.call(join, ...path);
	}

	/**
	 * Empty the bucket for the current service
	 */
	emptyServiceBucket() {
		var listAndDelete = function(bucketName) {
			return new Promise((resolve, reject) => {
				this.aws.s3.listObjects({
					Bucket: bucketName,
					MaxKeys: 1000
				}, (err, data) => {
					if(err) {
						reject(err);
					} else {
						// Delete the specified keys
						var promise = new Promise((resolve, reject) => {
							console.log('aws-apigateway: Deleting ' + data.Contents.length
							 	+ ' items');

							this.aws.s3.deleteObjects({
								Bucket: bucketName,
								Delete: {
									Objects: data.Contents.map((obj) => {
										return {
											Key: obj.Key
										};
									}),

									Quiet: true
								}
							}, function(err, deleteData) {
								if(err) {
									reject(err);
								} else {
									resolve(deleteData);
								}
							})
						});

						if(data.NextMarker) {
							promise = promise.then(() => {
								return this.emptyServiceBucket(bucketName);
							});
						}

						resolve(promise);
					}
				});
			});
		};

		return this.getServiceStackOutput('BucketName')
			.then((bucketName) => {
				console.log('aws-apigateway: Emptying the service\'s bucket.');

				return listAndDelete.call(this, bucketName);
			})
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
			return this.getServiceStackOutput('BucketName')
			.then((bucketName) => {
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

				return this.getServiceStackOutput('BucketName');
			})
			.then((bucketName) => {
				return new Promise((resolve, reject) => {
					this.aws.s3.putObject({
						Bucket: bucketName,
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
		console.log('aws-apigateway: Deleting the KMS key for the ' + stage
			+ ' stage and ' + region + ' region.');

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
				return Promise.resolve()
					.then(() => {
						return new Promise((resolve, reject) => {
							this.aws.kms.deleteAlias({
								AliasName: this.getKeyAlias(stage, region)
							}, function(err, data) {
								if(err) {
									reject(err);
								} else {
									resolve(data);
								}
							});
						});
					})
					.then(() => {
						return key;
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
