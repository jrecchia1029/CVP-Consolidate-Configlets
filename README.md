# Consolidate Device-Level Configlets

- [Description](#description)
- [Executing Script](#executing-script)
  - [Script Options](#script-options)
- [Workflow](#workflow)
  - [Consolidate Device-Level Configlets](#consolidate-device-level-configlets)

## Description
This script utilizes CVP's REST API to consolidate any configlets applied to a device at the device-level in CVP's Provisioning page to a single device level configlet:

## Executing Script
**It is best to run a compliance check on the target device or container in CVP before executing this script.**

To execute the script, navigate to the directory the `consolidate.py` file is and execute the following command:
```python consolidate.py --user <username> --password <password> --cvp <cvp-ip-address> --target <device-or-container-name> --mode extended --cancel True```

### Script Options
```
usage: consolidate.py [-h] [-u USER] [-p PASSWORD] [-host CVP] [-t TARGET]
                      [-m MODE] [-c CANCEL]

Provisions devices in CVP

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  Username for CVP user
  -p PASSWORD, --password PASSWORD
                        Password for CVP user
  -host CVP, --cvp CVP  CVP node IP Addresses separated by commas
  -t TARGET, --target TARGET
                        Name of device or container
  -m MODE, --mode MODE  Options are: 'extended' and 'immediate'. If a
                        container is provided to the target argument, the mode
                        will determine whether to fetch the devices whose
                        parent container is the target or all devices under
                        the target
  -c CANCEL, --cancel CANCEL
                        True/False. If set to true, will cancel any tasks
                        created by applying new configlet
```

- Note that if you do not wish to enter a password value in plain text, you may leave the password field out of the initial execution command and will be prompted for it when the script is executing.

## Workflow

1.  Script gets devices from CVP based on target argument.
2.  For each device retrieved, the script checks to see if the device is streaming to CVP and if its configuration is in compliance.  If so, the script continues to process the switch.
3.  A configlet named <switch-hostname> containing all device-level configuration (and no configuration that would be inherited from containers) is created/updated in CVP.
4.  The script will create an 'Update Config' task by removing any configlets applied to the device.
5.  The script will update that 'Update Config' task by applying the device-level configlet to the device.
6.  The script will then optionally cancel the 'Update Config' task or leave it be.

