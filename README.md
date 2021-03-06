# aerohive-autoroot
Privilege escalation on aerohive devices

# Tested devices

- AP130
- AP230

# Requirements
CLI access

# How to

```
go build .
./aerohive-autoroot --pubkey publickey.pub 10.0.0.1:22 # Where 10.0.0.1 is the device address
```

Wait until command completes then connect with:  

```
ssh root@10.0.0.1
```

# How it works
The Aerohive CLI has a flaw that allows code execution. Using this, it is possible to put a public key in the root users `.ssh/authorized_keys` file, and this gain full shell.
