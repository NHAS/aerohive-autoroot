# aerohive-autoroot
Remote code injection and privilege escalation on Aerohive devices.

# Tested devices

- AP130
- AP230
- AP330
- AP650

# Tested Firmware

- 10.0r9b and below

# Requirements
For older <10.0 firmware all that is required is network access to the device and the ability to connect to the management interface which typically runs on port 443.

For newer devices, a valid user needs to have logged in at least once to create a valid session file on the device. But it will work up until 10.0r9. 

# Instructions

This tool has a number of modes and tools that allow for manual access. Shown below is the help output.

```
usage:  aerohive-autoroot [options] <device ip>
        General
                --generate <mac>        Generate password list for system users, print to stdout
        Modes
                --no-access     Can connect to the aerohive device, but not login (Default)
                --rcli          Restricted command line access

        No Access Options
                --webport <port>        The web server port (Default: 443)
                --readfile <path>       Path to file to read off the server and print it to STDOUT (disables automatic cracking)

        Restricted CLI Access Options
                -u      Command line interface username
                -p      Command line interface password
                --pubkey <path> Path to your public key to write to device
```


If you have access to a restricted shell on the device, it is possible to gain full root `/bin/sh` access by dropping a public key into the `/root/.ssh` folder.
You'd do this in the tool by the following:

```
aerohive-autoroot --rcli --pubkey ~/.ssh/id_ed25519 192.168.1.1:22
```
This would default to using the default username/password `admin`/`aerohive`.  
  
For more complex exploitation, you have the no access options.  
This does require the device to have the web configuration portal accessible.  

Effectively you can use the automated part of the tool to crack default password of 'service' accounts that are automatically added with a new (easily guessible) password each reboot. 

```
aerohive-autoroot 192.168.1.1
```

Other tools you can use are the `generate` and `readfile` functionalities. 
Generate allows you to generate a list of possible passwords for the service accounts, if you have the mac address. I found it wasnt feasible to bruteforce the OpenSSH, due to you still having to attempt 1 million guesses. 

The readfile functionality requires you to have access to the web portal on the device, and will allow you to read any file off the device (as the web server is running as root).


# Limitations
On the newer firmware versions, If no user has ever logged into the web interface the web exploits will not work. Due to the authorisation essentially relying on a "is this file on the filesystem". 
If this file doesnt exist, then it isnt possible to initalise the php modules that have serious vulnerabilities. 
