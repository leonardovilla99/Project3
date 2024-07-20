import sys
from socket import socket, AF_INET, SOCK_DGRAM

# create DNS query message
def create_query(id, domain_name):
    # create the header for query
    first_row = (id).to_bytes(2, byteorder='big')
    second_row = (0).to_bytes(2, byteorder='big')
    qdcount = (1).to_bytes(2, byteorder='big')
    ancount = (0).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    header = first_row + second_row + qdcount + ancount + nscount + arcount

    # create the question for query
    qname = b''
    # split domain name into labels
    labels = domain_name.split('.')
    for label in labels:
        qname += len(label).to_bytes(1, byteorder='big')  # length byte
        qname += bytes(label, 'utf-8')  # label bytes
    # zero length byte as end of qname
    qname += (0).to_bytes(1, byteorder='big')
    qtype = (1).to_bytes(2, byteorder='big')
    qclass = (1).to_bytes(2, byteorder='big')
    question = qname + qtype + qclass

    return header + question

# parse byte_length bytes from index as unsigned integer, return number and index of next byte
def parse_unsigned_int(index, byte_length, response):
    num = int.from_bytes(
        response[index: index + byte_length], byteorder="big", signed=False)
    return num, index + byte_length

# parse name as label serie from index, return name and index of next byte
def parse_name(index, response):
    name = ''
    end = 0
    loop = True
    while loop:
        # end of label serie
        if response[index] == 0:
            loop = False
            if end == 0:
                end = index + 1
        # pointer
        elif response[index] >= int('11000000', 2):
            end = index + 2
            index = int.from_bytes(
                response[index: index + 2], byteorder="big", signed=False) - int('1100000000000000', 2)
        # label
        else:
            label_length = response[index]
            index += 1
            label = response[index: index + label_length].decode('utf-8')
            name += label
            index += label_length
            if response[index] != 0:
                name += '.'

    return name, end

# function to parse resource records
def parse_resource(count, index, response, ind_name):
    records = []
    for _ in range(count):
        # if index name has '.' need resync
        if ind_name:
            name, _ = parse_name(index, response)
            # resync index
            index += 2
        else:
            name, index = parse_name(index, response)
        rtype, index = parse_unsigned_int(index, 2, response)
        rclass, index = parse_unsigned_int(index, 2, response)
        ttl, index = parse_unsigned_int(index, 4, response)
        rlength, index = parse_unsigned_int(index, 2, response)
        rdata_start = index
        rdata = response[index:index + rlength]
        index += rlength
        if rtype == 2:  # NS record
            rdata_name, _ = parse_name(rdata_start, response)  # parse rdata as domain name
            records.append((name, rtype, rclass, ttl, rdata_name, index))
        else: # A record and others
            records.append((name, rtype, rclass, ttl, rdata, index))
    return records, index

# response is the raw binary response received from server
def parse_response(response):
    # current byte index
    index = 0
    id_p, index = parse_unsigned_int(index, 2, response)\
    # skip the next 2 bytes, i.e., second row (tags)
    index += 2
    qdcount, index = parse_unsigned_int(index, 2, response)
    ancount, index = parse_unsigned_int(index, 2, response)
    nscount, index = parse_unsigned_int(index, 2, response)
    arcount, index = parse_unsigned_int(index, 2, response)

    # parse question from qdcount
    questions = []
    for _ in range(qdcount):
        name, index = parse_name(index, response)
        qtype, index = parse_unsigned_int(index, 2, response)
        qclass, index = parse_unsigned_int(index, 2, response)
        questions.append((name, qtype, qclass))

    # parse answers from ancount
    answers, index = parse_resource(ancount, index, response, True)
    # parse authorities from nscount
    authorities, index = parse_resource(nscount, index, response, False)
    # parse additionals from arcount
    additionals, index = parse_resource(arcount, index, response, True)

    # return all data
    return {
        'id': id_p,
        'questions': questions,
        'answers': answers,
        'authorities': authorities,
        'additionals': additionals
    }

# funtion to print all variable into console
def print_response(response):
    # print Answers Section
    print("Answers Section:")
    for answer in response['answers']:
        name, rtype, rclass, ttl, rdata, _ = answer
        ip_address = '.'.join(map(str, rdata))
        print(f"\tName: {name} \tIP: {ip_address}")
    # print Authority Section
    print("Authority Section:")
    for authority in response['authorities']:
        name, rtype, rclass, ttl, rdata_name, _ = authority
        print(f"\tName: {name} \tName Server: {rdata_name}")
    # print Additional Information Section
    print("Additional Information Section:")
    for additional in response['additionals']:
        name, rtype, rclass, ttl, rdata, _ = additional
        ip_address = '.'.join(map(str, rdata))
        print(f"\tName: {name} \tIP: {ip_address}")

# sends a DNS query to a specified server and returns the parsed response
def query_dns(domain_name, dns_ip):
    sock = socket(AF_INET, SOCK_DGRAM)
    id = 1
    query = create_query(id, domain_name)
    sock.sendto(query, (dns_ip, 53))
    response, _ = sock.recvfrom(2048)
    parsed_response = parse_response(response)
    # reciving data
    print(f"Reply received. Content overview:")
    print(f"\t{len(parsed_response['answers'])} Answers.")
    print(f"\t{len(parsed_response['authorities'])} Intermediate Name Servers.")
    print(f"\t{len(parsed_response['additionals'])} Additional Information Records.")
    print_response(parsed_response)
    return parsed_response

# keeps querying servers until cannot find further servers to query
def resolve(domain_name, root_dns_ip):
    current_dns_ip = root_dns_ip
    while True:
        # query every dns (loop)
        print('----------------------------------------------------------------')
        print(f"DNS server to query: {current_dns_ip}")
        response = query_dns(domain_name, current_dns_ip)
        for answer in response['answers']:
            name, rtype, rclass, ttl, rdata, _ = answer
            if rtype == 1:  # A record
                ip_address = '.'.join(map(str, rdata))
                return
        next_dns_ip = None
        for additional in response['additionals']:
            name, rtype, rclass, ttl, rdata, _ = additional
            if rtype == 1:  # A record
                next_dns_ip = '.'.join(map(str, rdata))
                break
        if next_dns_ip:
            current_dns_ip = next_dns_ip
        else:
            return

# get domain-name and root-dns-ip from command line
if len(sys.argv) != 3:
    print('Usage: mydns domain-name root-dns-ip')
    sys.exit()
domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

# start looping ips
resolve(domain_name, root_dns_ip)
