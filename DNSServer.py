# DNS Client for Part 1 of the DNS assignment
# Fills in the missing parts from the skeleton code
import dns.resolver
 
# Set the IP address of the local DNS server and a public DNS server
local_host_ip = '127.0.0.1'  # localhost IP address
real_name_server = '8.8.8.8'  # I found Google's DNS server by researching online
 
 
# Create a list of domain names to query - use the same list from the DNS Server
domainList = ['example.com.','safebank.com.','google.com.','nyu.edu.','legitsite.com.']
 
# Define a function to query the local DNS server for the IP address of a given domain name
def query_local_dns_server(domain, question_type):
    """
    This function queries the local DNS server running on localhost
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [local_host_ip]
        # print(f"Querying local DNS for {domain}") # used this for debugging
        answers = resolver.resolve(domain, question_type)  # resolve the domain with question_type
     
        ip_address = answers[0].to_text()  # get the first answer
        return ip_address
    except dns.resolver.NXDOMAIN:
        return f"Domain {domain} does not exist"
    except Exception as e:
        return f"Error: {e}"
 
# Define a function to query a public DNS server for the IP address of a given domain name
def query_dns_server(domain, question_type):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [real_name_server]
    answers = resolver.resolve(domain, question_type)
 
    ip_address = answers[0].to_text()  # extract the first IP address
    return ip_address
 
# Define a function to compare the results from the local and public DNS servers for each domain name in the list
def compare_dns_servers(domainList, question_type):
    for domain_name in domainList:
        # get IP from local DNS
        local_ip_address = query_local_dns_server(domain_name, question_type)
        # get IP from public DNS
        public_ip_address = query_dns_server(domain_name, question_type)
        # if they don't match, return False
        if local_ip_address != public_ip_address:
            return False
    # if all match, return True
    return True    
 
# Define a function to print the results from querying both the local and public DNS servers for each domain name in the domainList
def local_external_DNS_output(question_type):    
    print("Local DNS Server")
    for domain_name in domainList:
        ip_address = query_local_dns_server(domain_name, question_type)
        print(f"The IP address of {domain_name} is {ip_address}")
 
 
    print("\nPublic DNS Server")
 
    for domain_name in domainList:
        ip_address = query_dns_server(domain_name, question_type)
        print(f"The IP address of {domain_name} is {ip_address}")
 
 
def exfiltrate_info(domain, question_type):  # testing method for part 2
    data = query_local_dns_server(domain, question_type)
    return data 
 
 
if __name__ == '__main__':
 
    # Set the type of DNS query to be performed
    question_type = 'A'  # for IPv4 addresses
 
 
    # Call the function to print the results from querying both DNS servers
    local_external_DNS_output(question_type)
 
    # Call the function to compare the results from both DNS servers and print the result
    compare_result = compare_dns_servers(domainList, question_type)
    print(f"Are the DNS results the same? {compare_result}")
    
    # According to assignment we need to test a specific domain
    nyu_ip = query_local_dns_server('nyu.edu.', question_type)
    print(f"The IP for nyu.edu is: {nyu_ip}")
