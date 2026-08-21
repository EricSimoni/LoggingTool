# Fedora Database Setup Guide

This guide provides step-by-step instructions for setting up PostgreSQL, pgAdmin, rsyslog, and configuring firewalld logging on Fedora Linux for the intrusion logger.

## Prerequisites

- Fedora Linux
- Root or sudo access
- PostgreSQL database server

## Install PostgreSQL

Follow the official Fedora PostgreSQL documentation:
https://docs.fedoraproject.org/en-US/quick-docs/postgresql/

```bash
# Install PostgreSQL
sudo dnf install postgresql postgresql-server

# Initialize the database
sudo postgresql-setup --initdb

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

## Install pgAdmin

Install pgAdmin from the official site (do not use dnf or yum):
https://www.pgadmin.org/download/pgadmin-4-rpm/

For SSH tunneling in pgAdmin after database setup:
https://www.enterprisedb.com/blog/ssh-tunneling-pgadmin-4

## Install and Configure rsyslog

```bash
# Install rsyslog
sudo dnf install rsyslog

# Restart and check status
sudo systemctl restart rsyslog
sudo systemctl status rsyslog
```

## Understanding firewalld Logs

firewalld uses nftables by default. This is why `iptables -L -n` will always be empty.

### Log Field Descriptions

- **IN=ens33**: Interface from which the packet arrived
- **OUT=**: Outgoing interface (usually empty)
- **MAC=**: Source and destination MAC addresses
- **SRC=**: Source IP address
- **DST=**: Destination IP address (your system)
- **LEN=**: Packet length in bytes
- **TOS=**: Type of service
- **PREC=**: Precedence type of service
- **TTL=**: Time To Live for the packet
- **ID=**: Unique ID of the IP datagram
- **DF**: "Do not fragment" flag of TCP
- **PROTO=**: Protocol used for transmission (TCP, UDP, etc.)
- **SPT=**: Source port
- **DPT=**: Destination port
- **WINDOW=**: TCP window size
- **RES=**: Reserved bits
- **SYN**: Request to make new connection
- **URGP=**: Urgent pointer (0 means connection not established)
- **ACK**: Acknowledgment flag (packet successfully received)
- **PSH**: Push flag (data passed to application immediately)

## Database Setup

### Create Database

Replace `[username-here]` with your desired username:

```sql
-- Database: intrusion
CREATE DATABASE intrusion
    WITH
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    LOCALE_PROVIDER = 'libc'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1
    IS_TEMPLATE = False;

GRANT TEMPORARY, CONNECT ON DATABASE intrusion TO PUBLIC;
GRANT ALL ON DATABASE intrusion TO [username-here];
GRANT ALL ON DATABASE intrusion TO postgres;
```

### Create Schema

```sql
-- SCHEMA: eng_ops
CREATE SCHEMA IF NOT EXISTS eng_ops
    AUTHORIZATION postgres;

COMMENT ON SCHEMA eng_ops
    IS 'schema for engineering operations';

GRANT ALL ON SCHEMA eng_ops TO [username-here];
GRANT ALL ON SCHEMA eng_ops TO postgres;
```

### Update PostgreSQL Authentication

Update PostgreSQL configuration files to allow logins. PostgreSQL logs can be found at:
```
/var/lib/pgsql/data/log
```

## Apply Database Schema

The base table schema is provided in `sql/000_base_table.sql`. Apply it:

```bash
psql -U postgres -d intrusion -f sql/000_base_table.sql
```

The enrichment table schema is provided in `sql/001_enrichment_table.sql`. Apply it:

```bash
psql -U postgres -d intrusion -f sql/001_enrichment_table.sql
```

## Configure rsyslog for firewalld Logging

Create `/etc/rsyslog.d/firewalld_log.conf`:

```rsyslog
# Load the PostgreSQL output module
module(load="ompgsql")

# Template for SQL insert with DF field
template(
    name="FirewallLogSQL" 
    type="string" 
    option.stdsql="on" 
    string="INSERT INTO eng_ops.firewall_logs (log_time, from_host, facility, priority, devicereportedtime, recievedat, infounitid, syslogtag, action, interface, mac_address, src_ip, dst_ip, len, tos, prec, ttl, ip_id, df, protocol, spt, dport, window_size, res, syn, urgp, message) VALUES (NOW(), '%HOSTNAME%', %syslogfacility%, '%syslogpriority%', '%timereported:::date-rfc3339%', '%timegenerated:::date-rfc3339%', %iut%, '%syslogtag%', '%$!action%', '%$!in_interface%', '%$!mac_address%', '%$!src_ip%', '%$!dst_ip%', '%$!len%', '%$!tos%', '%$!prec%', '%$!ttl%', '%$!ip_id%', '%$!df%', '%$!protocol%',  '%$!spt%', '%$!dport%', '%$!window%', '%$!res%','%$!syn%','%$!urgp%',   '%$!message%');"
)

# Template for SQL insert where DF field does not show up
template(
    name="FirewallLogSQL_NULL" 
    type="string" 
    option.stdsql="on" 
    string="INSERT INTO eng_ops.firewall_logs (log_time, from_host, facility, priority, devicereportedtime, recievedat, infounitid, syslogtag, action, interface, mac_address, src_ip, dst_ip, len, tos, prec, ttl, ip_id, df, protocol, spt, dport, window_size, res, syn, urgp, message) VALUES (NOW(), '%HOSTNAME%', %syslogfacility%, '%syslogpriority%', '%timereported:::date-rfc3339%', '%timegenerated:::date-rfc3339%', %iut%, '%syslogtag%', '%$!action%', '%$!in_interface%', '%$!mac_address%', '%$!src_ip%', '%$!dst_ip%', '%$!len%', '%$!tos%', '%$!prec%', '%$!ttl%', '%$!ip_id%', NULL, '%$!protocol%',  '%$!spt%', '%$!dport%', '%$!window%', '%$!res%','%$!syn%','%$!urgp%',   '%$!message%');"
)

# Parse firewall logs without DF field
if ($msg contains "IN=" and ($msg contains 'REJECT' or $msg contains 'DENIED') and not ($msg contains " DF ")) then
{
  set $!malware = "(PotentiallyDangerous)VirusXYZ";
  set $!action = field($msg,32,1);
  set $!in_interface = field($msg,32,2);
  set $!out_interface = field($msg,32,3);
  set $!mac_address = field($msg,32,4);
  set $!src_ip = field($msg,32,5);
  set $!src_ip = field($!src_ip,61,2);
  set $!dst_ip = field($msg,32,6);
  set $!dst_ip = field($!dst_ip,61,2);
  set $!len = field($msg,32,7);
  set $!len = field($!len,61,2);
  set $!tos = field($msg,32,8);
  set $!tos = field($!tos,61,2);
  set $!prec = field($msg,32,9);
  set $!prec = field($!prec,61,2);
  set $!ttl = field($msg,32,10);
  set $!ttl = field($!ttl,61,2);
  set $!ip_id = field($msg,32,11);
  set $!ip_id = field($!ip_id,61,2);
  set $!protocol = field($msg,32,12);
  set $!protocol = field($!protocol,61,2);
  set $!spt = field($msg,32,13);
  set $!spt = field($!spt,61,2);
  set $!dport = field($msg,32,14);
  set $!dport = field($!dport,61,2);
  set $!window = field($msg,32,15);
  set $!window = field($!window,61,2);
  set $!res = field($msg,32,16);
  set $!res = field($!res,61,2);
  set $!syn = field($msg,32,17);
  set $!urgp = field($msg,32,18);
  set $!urgp = field($!urgp,61,2);
  set $!message = $msg;

  action(
    type="ompgsql"
    server="127.0.0.1"
    db="intrusion"
    user="intrusion_logger"
    pass="your_password"
    template="FirewallLogSQL_NULL" 
  )
  stop
}
else
{
  # Parse firewall logs with DF field
  if  ($msg contains "IN=" and ($msg contains 'REJECT' or $msg contains 'DENIED') and $msg contains " DF ") then
  {
    set $!malware = "(PotentiallyDangerous)VirusXYZ";
    set $!action = field($msg,32,1);
    set $!in_interface = field($msg,32,2);
    set $!out_interface = field($msg,32,3);
    set $!mac_address = field($msg,32,4);
    set $!src_ip = field($msg,32,5);
    set $!src_ip = field($!src_ip,61,2);
    set $!dst_ip = field($msg,32,6);
    set $!dst_ip = field($!dst_ip,61,2);
    set $!len = field($msg,32,7);
    set $!len = field($!len,61,2);
    set $!tos = field($msg,32,8);
    set $!tos = field($!tos,61,2);
    set $!prec = field($msg,32,9);
    set $!prec = field($!prec,61,2);
    set $!ttl = field($msg,32,10);
    set $!ttl = field($!ttl,61,2);
    set $!ip_id = field($msg,32,11);
    set $!ip_id = field($!ip_id,61,2);
    set $!df = field($msg,32,12);
    set $!protocol = field($msg,32,13);
    set $!protocol = field($!protocol,61,2);
    set $!spt = field($msg,32,14);
    set $!spt = field($!spt,61,2);
    set $!dport = field($msg,32,15);
    set $!dport = field($!dport,61,2);
    set $!window = field($msg,32,16);
    set $!window = field($!window,61,2);
    set $!res = field($msg,32,17);
    set $!res = field($!res,61,2);
    set $!syn = field($msg,32,18);
    set $!urgp = field($msg,32,19);
    set $!urgp = field($!urgp,61,2);
    set $!message = $msg;

    action(
      type="ompgsql"
      server="127.0.0.1"
      db="intrusion"
      user="intrusion_logger"
      pass="your_password"
      template="FirewallLogSQL" 
    )
    stop
  }
}
```

**Important**: Replace the following values in the rsyslog configuration:
- `db="intrusion"` - Your database name
- `user="intrusion_logger"` - Your database user
- `pass="your_password"` - Your database password

## Restart rsyslog

After creating the configuration file, restart rsyslog:

```bash
sudo systemctl restart rsyslog
sudo systemctl status rsyslog
```

## Verify Setup

Check that firewall logs are being written to the database:

```bash
# Connect to PostgreSQL
sudo -u postgres psql -d intrusion

# Check for firewall logs
SELECT COUNT(*) FROM eng_ops.firewall_logs;

# View recent logs
SELECT * FROM eng_ops.firewall_logs ORDER BY log_time DESC LIMIT 10;
```

## Troubleshooting

- Check PostgreSQL logs: `/var/lib/pgsql/data/log`
- Check rsyslog logs: `journalctl -u rsyslog`
- Verify PostgreSQL is accepting connections: `sudo systemctl status postgresql`
- Test rsyslog configuration: `rsyslogd -N1`
