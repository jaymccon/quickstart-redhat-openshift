import cfnresponse
import logging
import os
import boto3

log = logging.getLogger(__name__)

def parse_properties(properties):
    cf_params = {'Capabilities': ['CAPABILITY_IAM',
                                  'CAPABILITY_AUTO_EXPAND',
                                  'CAPABILITY_NAMED_IAM'],
                'DisableRollback': True
    }
    cf_params["Parameters"] = []
    for key, value in properties.items():
        if key == "TemplateURL":
            cf_params["TemplateURL"] = value
        elif key == "StackName":
            cf_params["StackName"] = value
        elif key == "KeyToUpdate":
            cf_params["KeyToUpdate"] = value
        elif key == "ServiceToken" or key == "Function" or key == "NumStacks":
            log.debug("Skipping over unneeded keys")
        else:
            temp = {'ParameterKey': key, 'ParameterValue': value}
            log.debug(temp)
            cf_params["Parameters"].append(temp)
    return cf_params

def handler(event, context):
    """
    The main Lambda handler
    """
    status = cfnresponse.SUCCESS
    cluster_info = {
            'status': 'complete'
            }
    level = logging.getLevelName(os.getenv('LogLevel'))
    log.setLevel(level)
    log.debug(event)

    if 'RequestType' in event.keys():
        try:
            if event['RequestType'] == 'Delete':
                log.info("Deleting all stacks in {} deployment'.format(cluster_name)")
            elif event['RequestType'] == 'Update':
                log.info("Update sent, however, this is unsupported at this time.")
                pass
            else:
                cf_client = boto3.client('cloudformation')
                cf_params = parse_properties(event['ResourceProperties'])
                log.info("Delete and Update not detected, proceeding with Create")
                #openshift_install_package = openshift_install_binary \
                #                            + openshift_install_os \
                #                            + openshift_version \
                #                            + file_extension
                #log.info("Generating OCP installation files for cluster " + cluster_name)
                #install_dependencies(openshift_client_mirror_url,
                #                     openshift_install_package,
                #                     openshift_install_binary,
                #                     download_path)
                if not cluster_info["status"]:
                    log.debug("STACK: {}".format(stack))
                    cluster_info["status"] = "building"
            log.info("Complete")
        except Exception:
            logging.error('Unhandled exception', exc_info=True)
            status = cfnresponse.FAILED
        finally:
            cfnresponse.send(event, context, status, {}, None)
    else:
        status = cfnresponse.FAILED
        cfnresponse.send(event, context, status, {}, None)
