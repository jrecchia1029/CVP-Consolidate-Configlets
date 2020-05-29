from cvprac.cvp_client import CvpClient
from cvprac.cvp_client_errors import CvpApiError
#Disables no certificate CVP warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json, re, csv
import argparse
from getpass import getpass

def updateInCVP(cvp, name, config):
    '''
    Args:
        name (str) -> name of the configlet
        config (str) -> content of configlet
        serial_number (str) -> device serial number
    Returns list of taskIds if any [1, 21]
    '''
    #Attempt to get config
    try:
        configlet_exists = cvp.api.get_configlet_by_name(name)
    except:
        # print ("Configlet {} doesn't exist".format(name))
        configlet_exists = None
    
    #Configlet does not exist
    if configlet_exists is None:
        #add new configlet to CVP
        configlet = cvp.api.add_configlet(name, config)
    #Configlet already exists
    else:
        #update existing configlet
        key = configlet_exists["key"]
        tasks = cvp.api.update_configlet(config, key, name, wait_task_ids=True)

def consolidate_configlets(cvp, device_dict, include_container_configlets=False, cancel_tasks=False):
    '''
        Creates a static configlet of the reconcile config produced as if no configlets are applied to the device
        Then deploys device into proper container based off of first three characters of device hostname and applies previously generated configlet
    '''
    configlets_to_generate_reconcile = []
    configlets_to_apply = []
    if device_dict["streamingStatus"] == "inactive":
        print("{} - Device is not streaming data to CVP".format(device_dict["hostname"]))
        return
    if device_dict["complianceCode"] in ["0001", "0003", "0008", "0009"]:
        print("{} - Device's configuration is out of compliance".format(device_dict["hostname"]))
        return
    #get device information from CVP
    print("{} - Getting device information...".format(device_dict["hostname"]))
    # print "Device"
    # print json.dumps(device_dict)
    # print "\n\n"
    device_id = device_dict["systemMacAddress"]
    
    # print "Configlets"
    # print json.dumps(configlets)
    # print "\n\n"

    print("{} - Got device information".format(device_dict["hostname"]))

    #keys of configlets we'll pretend are applied to a device when we generate a reconcile config
    if include_container_configlets == True:
        container_configlet_keys = [ configlet["key"] for configlet in cvp.api.get_configlets_inherited_from_containers(device_dict['containerName']) ]
    else:
        container_configlet_keys = []

    configlets_to_generate_reconcile = container_configlet_keys

    #Generate consolidated configlet
    print ("{} - Generating configlet configuration...".format(device_dict["hostname"]))
    validate_response = cvp.api.validate_configlets_for_device(device_id, configlets_to_generate_reconcile,
                                       page_type='validate')

    if "runningConfig" in validate_response.keys():
        config = []
        for line in validate_response["runningConfig"]:
            if include_container_configlets == True:
                if line["command"] == "!":
                    config.append(line["command"])
                elif line["shouldReconcile"] == True:
                    config.append(line["command"])
                else:
                    continue
            else:
                config.append(line["command"])

        # Parse out duplicate '!'s
        parsed_config = []
        for i, line in enumerate(config):
            if i != 0:
                if not(line == "!" and config[i-1] == "!"):
                    parsed_config.append(line)
        config = parsed_config

        config = "\n".join(config)
    else:
        print("{} - No reconcile configlet to generate.".format(device_dict["hostname"]))
        return

    #Create and apply consolidated configlet
    configlet_name = device_dict["hostname"]

    #Create New Configlet
    print ("{} - Updating/Creating configlet...".format(device_dict["hostname"]))
    updateInCVP(cvp, configlet_name, config)
    print ("{} - Updated/Created configlet".format(device_dict["hostname"]))

    try:
        configlet_to_apply = cvp.api.get_configlet_by_name(configlet_name)
    except CvpApiError as e:
        configlet_to_apply = None

    if configlet_to_apply is not None:
        configlets_to_apply.append(configlet_to_apply)
    else:
        print("{} - Could not find configlet named {}".format(configlet_name, device_dict["hostname"]))
        return

    if device_dict["parentContainerKey"] == "undefined_container":
        print("{} is in Undefined container.  Will not create changes.".format(device_dict["hostname"]))

    #Get already applied configlets at device level
    device_level_configlets = cvp.api.get_configlets_by_netelement_id(device_id)["configletList"]
    print("{} - Removing device-level configlets...".format(device_dict["hostname"]))
    cvp.api.remove_configlets_from_device("Removed by script", device_dict, device_level_configlets)
    print("{} - Applying single configlet at device-level...".format(device_dict["hostname"]))
    tasks = cvp.api.apply_configlets_to_device("Added by script", device_dict, configlets_to_apply)
    try:
        taskIds = tasks["data"]["taskIds"]
    except KeyError as e:
        print(e)
        return

    if cancel_tasks == True:
        print("{} - Cancelling any created tasks created by applying config...".format(device_dict["hostname"]))
        for task in taskIds:            
            cvp.api.cancel_task(task)
        print("{} - Cancelled task".format(device_dict["hostname"]))

    return

def parseArgs():
    parser = argparse.ArgumentParser(
        description='Provisions devices in CVP')

    parser.add_argument('-u', '--user', help="Username for CVP user")
    parser.add_argument('-p', '--password', default=None, help="Password for CVP user")
    parser.add_argument('-host', '--cvp', help="CVP node IP Addresses separated by commas")
    parser.add_argument('-t', '--target', help="Name of device or container")
    parser.add_argument('-m', '--mode', default="extended",
    help="Options are: 'extended' and 'immediate'. If a container is provided to the target argument, the mode will determine whether to fetch the devices whose parent container is the target or all devices under the target")
    parser.add_argument('-c', '--cancel', default=False, help="True/False.  If set to true, will cancel any tasks created by applying new configlet")
    args = parser.parse_args()

    return args

def main():
    args = parseArgs()
    username = args.user
    password = args.password
    if password is None:
        print("Please provide a password for the user {}".format(username))
        password = getpass("Password:")
    cvp_addresses = [ address.strip() for address in  args.cvp.split(",") ]

    cvp = CvpClient()
    cvp.connect(cvp_addresses, username, password)

    #Define list of switches we will consolidate configlets
    switches = []

    print("Retrieving inventory")
    #Check if target is a container
    container = None
    containers = cvp.api.get_containers()["data"]
    for c in containers:
        if c["name"] == args.target:
            container = c
            break
    
    #If no container is found from the target name, assume it is a device
    if container is not None:
        #Get devices in/under container
        if args.mode == "extended":
            switches = cvp.api.get_devices_under_container(args.target)
        else:
            switches = cvp.api.get_devices_in_container(args.target)
    
    else:
        inventory = cvp.api.get_inventory()
        for device in inventory:
            if device['hostname'] == args.target:
                switches.append(device)
                break
    print("Successfully retrieved inventory")
    cancel_tasks = True if re.match(r'(?i)True', args.cancel) else False
    for switch in switches:
        #Check to see if switch in spreadsheet and get VRF 
        consolidate_configlets(cvp, switch, include_container_configlets=True, cancel_tasks=cancel_tasks)

if __name__ == "__main__":
    main()