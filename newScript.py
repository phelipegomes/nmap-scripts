import re
import csv

def parse_nmap_output(nmap_output):
    results = []
    current_entry = {}

    for line in nmap_output:
        if re.match(r'^Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line):
            if current_entry:
                results.append(current_entry)
            ip_address = re.search(r'\d+\.\d+\.\d+\.\d+', line).group(0)
            current_entry = {'ip': ip_address}
        elif re.match(r'^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)', line):
            match = re.match(r'^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)', line)
            port = match.group(1)
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)

            if 'ports' not in current_entry:
                current_entry['ports'] = []

            current_entry['ports'].append({
                'port': f'{port}/{protocol}',
                'state': state,
                'service': service
            })
        elif '| vulners:' in line:
            vulners_match = re.search(r'\| vulners: (.+)$', line)
            if vulners_match:
                vulners_info = vulners_match.group(1).strip().split(',')
                if 'vulners' not in current_entry:
                    current_entry['vulners'] = []
                current_entry['vulners'].append({
                    'info': vulners_info[0],
                    'score': vulners_info[1],
                    'link': vulners_info[2],
                    'exploit': vulners_info[3] if len(vulners_info) > 3 else ''
                })

    if current_entry:
        results.append(current_entry)

    return results

def write_to_csv(output_file, data):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'port', 'service', 'version', 'vulners']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()

        for entry in data:
            ip = entry['ip']
            for port_info in entry.get('ports', []):
                writer.writerow({
                    'ip': ip,
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'version': port_info.get('version', ''),
                    'vulners': ''
                })
                if 'vulners' in entry:
                    for vulners_info in entry['vulners']:
                        writer.writerow({
                            'ip': ip,
                            'port': port_info['port'],
                            'service': port_info['service'],
                            'version': port_info.get('version', ''),
                            'vulners': f"{vulners_info['info']} {vulners_info['score']} {vulners_info['link']} {vulners_info['exploit']}"
                        })

if __name__ == "__main__":
    input_file = 'nmap_output.txt'
    output_file = 'output.csv'

    with open(input_file, 'r') as file:
        nmap_output = file.readlines()

    parsed_data = parse_nmap_output(nmap_output)
    write_to_csv(output_file, parsed_data)
    print(f"CSV file '{output_file}' has been generated.")
