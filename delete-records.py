import dns.resolver
import dns.update
import dns.query
import dns.zone
import dns.reversename

# Configure your DNS server details
DNS_SERVER = 'your.dns.server.ip'
DNS_KEY_NAME = 'your-key-name'  # Replace with your TSIG key name if used
DNS_KEY_SECRET = 'your-base64-secret'  # Replace with your TSIG key secret
ZONE_NAME = 'your.zone.name'  # Replace with your zone name (e.g., 0.168.192.in-addr.arpa)
def query_ptr_records(ip_address):
    """
    Query all PTR records for a given IP address.
    :param ip_address: str, the IP address to query.
    :return: list of PTR records.
    """
    try:
        # Convert IP address to reverse DNS name
        reverse_name = dns.reversename.from_address(ip_address)
        
        # Query for PTR records
        answers = dns.resolver.resolve(reverse_name, 'PTR')
        
        # Extract and return the PTR records
        ptr_records = [str(rdata) for rdata in answers]
        return ptr_records
    except dns.resolver.NoAnswer:
        print(f"No PTR records found for IP address {ip_address}.")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"No reverse DNS entry found for IP address {ip_address}.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
# Criteria for identifying bogus records
def is_bogus(ptr_record: str) -> bool:
    """
    Define criteria for identifying bogus PTR records.
    For example:
    - Does not resolve to a valid A record
    - Contains unexpected values
    """
    try:
        dns.resolver.resolve(ptr_record, 'A')
        return False  # Valid record
    except dns.resolver.NXDOMAIN:
        return True  # Bogus record
    except Exception as e:
        print(f"Error resolving {ptr_record}: {e}")
        return True  # Treat as bogus in case of unexpected errors


def delete_ptr_records():
    # Fetch the zone
    print("Fetching the zone...")
    zone = dns.zone.from_xfr(dns.query.xfr(DNS_SERVER, ZONE_NAME))
    
    # Prepare for updates
    update = dns.update.Update(ZONE_NAME, keyring=dns.tsigkeyring.from_text({DNS_KEY_NAME: DNS_KEY_SECRET}))
    
    # Iterate through PTR records in the zone
    for name, node in zone.nodes.items():
        rdataset = node.rdatasets
        for rdata in rdataset:
            if rdata.rdtype == dns.rdatatype.PTR:
                ptr_record = rdata.to_text()
                if is_bogus(ptr_record):
                    print(f"Deleting bogus PTR record: {name} -> {ptr_record}")
                    update.delete(name, rdata)
    
    # Send update to DNS server using UDP
    print("Sending updates to the DNS server...")
    dns.query.udp(update, DNS_SERVER)
    print("Update complete.")


if __name__ == "__main__":
    try:
        delete_ptr_records()
    except Exception as e:
        print(f"An error occurred: {e}")
