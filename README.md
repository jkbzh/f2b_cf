# f2b_cf: manage cloudflare's custom IP Lists using fail2ban and python
`f2b_cf` is Python cli script that allows
[fail2ban](https://github.com/fail2ban/fail2ban) to interact with cloudflare's
IP lists in the same way that fail2ban interacts with iptables. The script is built on top of Cloudflare's [Python API library](https://github.com/cloudflare/cloudflare-python).

`f2b_cf` is linked with a fail2ban jail using fail2ban actions. The actions
specify how f2b_cf is called to manage a cloudflare [IP
list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/#lists-with-ip-addresses-ip-lists). In
clouflare, you use these IP Lists as part of your
[WAF](https://developers.cloudflare.com/waf/) to define your firewall policy to
access one or more services.

`f2b_cf` is also a stand-alone cli which lets you interact directly with your
cloudflare IP list.

## Installation and Configuration

Installing and configuring fb2_cf require you to

- set up your cloudflare IP Lists and Account API Token
- set up a python virtual environment
- configure and install the f2b_cf scripts and actions

We assume that you have already installed fail2ban and that its configuration
files are available at `/etc/fail2ban/`.

### Cloudflare configuration

Configuration requires setting up IP lists and an an account API token in
cloudflare, updating the f2b_cf configuration file with that info, and refering
to the f2b_cf from your fail2ban jails.

1.1 Create a [cloudflare custom IP list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/#lists-with-ip-addresses-ip-lists) for temporary bans and, optionally, a second one
   for permanent bans. Write down each list's ID as we'll use them later on.
   
1.2 Create a [cloudflare Account API
   token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
   granting the holder permissions to manage the IP Lists previously
   created. (permissions: `Account` `Account IP Lists` `Edit`). Remember to set
   the `Client IP Address filtering` to limit the client's IP addresses that
   can use the API token. Write down the API token's value.

1.3 Write down your `cloudflare account ID` as you'll need it later on.

### Python virtual environment

Installation requires setting up and populating a [python virtual
environment](https://docs.python.org/3/library/venv.html)

2.1 Create a local python3 virtual environment
```
sudo python3 -m venv /path/to/new/virtual/environment
```

2.2 Install the required python packages into the new virtual environment

```
sudo /path/to/new/virtual/environment/bin/pip3 install -r requirements.txt
```

### Configuring and installing f2b_cf

In this step, you'll create the f2b_cf and copy it as well as the f2b_cf
scripts to their target destination


3.1 Initialize the f2b_cf with your cloudflare account ID, IP lists IDs, and
API token you created in steps 1.1 and 1.2.
```
cp f2b_cf.conf.dist f2b_cf.conf  
edit f2b_cf.conf
```
3.2. Install the configuration file. Make sure you set the access rights
   correctly so that f2b_cf can access it while preserving your token's
   privacy
```
sudo cp f2b_cf.conf /etc/
# adjust the owner, group and access rights according to your needs
sudo chown root:root /etc/f2b_cf.conf
sudo chmod 0640 /etc/f2b_cf.conf
```


3.3. Configure f2b_cf, a helper script to simplify calling f2b_cf.py, so that
   it uses the python interpreter from the virtual environment you created in
   step 2.1 and the configuration file from step 3.2.

```
sudo cp f2b_cf.dist f2b_cf
sudo edit f2b_cf
```

3.4 Copy the f2b_cf and f2b_cf.py scripts to their target destination.

```
sudo cp f2b_cf f2b_cf.py /usr/local/sbin/
# adjust the owner, group and access rights according to your needs
sudo chown root:root /usr/local/sbin/{f2b_cf,f2b_cf.py}
sudo chmod 0640 /usr/local/sbin/{f2b_cf,f2b_cf.py}
```

3.5 Test the script's configuration and cloudflare API token, IP list setup. We
assume that f2b_cf and f2b_cf.py are in your PATH.

```
sudo f2b_cf --help
sudo f2b_cf --test
```

## Configure and install the f2b_cf fail2ban actions

4.1 Configure the fail2ban actions so that they can find the `f2b_cf` script

```
cd action.d/
cp f2b-cf-common.conf.dist f2b-cf-common.conf
# If f2b_cf is not in your PATH, hard-code its location
edit f2b-cf-common.conf
```

4.2 (Optional) Customize the fail2ban temp-ban and perma-ban actions

The distribution temp-ban and perma-ban actions are set up so that
fail2ban manages everything for the temp-ban actions (adding, deleting,
flushing), but only does add for perma-ban, letting you manually manage that
list by means of the cli or the cloudflare dashboard.

Depending on your use and installation of fail2ban, you may need to adjust
these actions. For example, in some setups, a cronjob daily stops fail2ban,
deletes the sqllite db associated with fail2ban, and then restarts fail2ban.
In this case, you'd need to adjust the start and stop actions so that the 
IP List is cleared when fail2ban is stop / started.

You can adjust the files to this behavior by calling the actions
custom-f2-bcf-temp-ban and adjusting its behavior, then refering to your custom
action in your jail. If you want to change or skip the default behavior that's
defined in f2b-cf-common.conf, just leave the action assignment blank.
```
edit f2b-cf-temp-ban.conf
edit f2b-cf-perma-ban.conf
```

Browse [fail2ban
actions](https://www.digitalocean.com/community/tutorials/how-fail2ban-works-to-protect-services-on-a-linux-server#examining-the-action-file)
for more info.

4.3 Copy the f2b_cf actions to the fail2ban action.d directory

Adjust the lines here below if you created your own custom actions.

```
sudo cp f2b-cf-common.conf  f2b-cf-perma-ban.conf  f2b-cf-temp-ban.conf \
   /etc/fail2ban/action.d/
# adjust the following according to your setup
sudo chown root:root \
   /etc/fail2ban/action.d/{f2b-cf-common.conf,f2b-cf-perma-ban.conf,f2b-cf-temp-ban.conf}
sudo chmod 0644 \
  /etc/fail2ban/action.d/{f2b-cf-common.conf,f2b-cf-perma-ban.conf,f2b-cf-temp-ban.conf}
```

### Bind the f2b_cf actions with your jail

5.1 Associate the appropriate new action with your fail2ban jail

To use a f2b-cf actions, you just need to include it in your jail definition.

In the example below, we binded the jail `thelounge` with the action
`f2b-cf-temp-ban` (no need to add the `.conf` extension).

```
[thelounge]
enabled = true
action = f2b-cf-temp-ban
bantime = 3600
filter = thelounge-auth
findtime = 600
backend = systemd
maxretry = 5
ignoreip = 192.0.2.1
```

Use `f2b-cf-temp-ban` for a temporary ban, `f2b-cf-perma-ban` for a "permanent"
ban, or your own derived custom actions.

5.2 Restart fail2ban to take into account the changes

Remember to always restart fail2ban if you add or edit new actions or jails.

```
sudo systemctl restart fail2ban
```

## Test your setup

6.1 List current bans

Here below we assume our jail is called `thelounge`. 
Our cloudflare IP List is called `f2b_thelounge`.

In these examples we use the `fail2ban-client` cli to force banning and
unbanning an IP address. These actions are otherwise done automatically by your
jail.

- Check current bans

```
$ fail2ban-client status thelounge
...
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
```

- Ban an IPv6 address (works with IPv4 too)

```
$ fail2ban-client set thelounge banip 2001:0000:130F:0000:0000:09C0:876A:130B
1

$ fail2ban-client status thelounge
Status for the jail: thelounge
...
`- Actions
   |- Currently banned: 1
   |- Total banned:     1
   `- Banned IP list:   2001:0:130f::9c0:876a:130b
```

- Check that the IP List contains the same IP address

Note that `f2b_cf` canonicalizes the IPv6 address to the format the cloudflare IP
List expects.

```
$ f2b_cf --dump
list 'f2b_thelounge' has 1.0 items
id: <the_ip_list_id>, ip: 2001:0:130f::/64
```

- Delete the ban

```
$ fail2ban-client set thelounge unbanip 2001:0:130f::9c0:876a:130b
1
```

- Check that the corresponding IP list entry was deleted

```
$ f2b_cf --dump
list 'f2b_thelounge' has 0.0 items
```

## List of f2b_cf commands

If you need to interact directly with the IP List without using the
fail2ban-client, you can use the f2b_cf script. 

Note: You can use either IPv6 or IPv4 indistinctly. The script recognizes both
of them.


- show available script commands
```
f2b_cf -h
```

- display version number
```
f2b_cf -v
```

- ban an IP address
```
f2b_cf -b 2001:0000:130F:0000:0000:09C0:876A:130B
```

- unban an IP address
```
f2b_cf -u 2001:0000:130F:0000:0000:09C0:876A:130B
```

- clear all bans
```
f2b_cf -c
```

- dump the contents of the ban IP list
```
f2b_cf -d
```

- Use the permanent ban list
Add the -p flag to select the permanent ban list as target of the command
(applies to all commands above)
```
f2b_cf -b 2001:0000:130F:0000:0000:09C0:876A:130B -p
```

- give an alternate location for the configuration file (applies to all
commands above)
```
f2b_cf -f /path/to/config_file.txt -d
```
