# aerohive-autoroot
Privilege escalation on aerohive devices

# Tested devices

- AP130
- AP230
- AP330

# Requirements
Network access to the device

# How do

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


If you have acess to a restricted shell on the device, it is possible to gain full ssh access by dropping a public key into the `/root/.ssh` folder.
You'd do this in the tool by the following:

```
aerohive-autoroot --rcli --pubkey ~/.ssh/id_ed25519 192.168.1.1
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

Some other work done on these devices can be found here: https://github.com/eriknl/CVE-2020-16152
This utilises another PHP bug to gain immediate shell execution on the device. 


# Limitations
- Currently works on up to firmware 10.0r7a, at this point the auth has changed. And I havent yet worked out a way around it.

# Todo

- Test all the things