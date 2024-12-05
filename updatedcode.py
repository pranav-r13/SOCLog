import re
import xml.etree.ElementTree as ET

def parse_fortisiem_log(log_message):
    # Dictionary to hold the parsed data
    log_dict = {}
    
    # Regular expression to match key-value pairs within square brackets (e.g., [key]="value")
    regex = r'\[([^\]]+)\]="([^"]+)"'
    
    # Find all key-value pairs using regex
    matches = re.findall(regex, log_message)
    
    # Add matches to dictionary
    for key, value in matches:
        log_dict[key] = value
    
    # Extract the XML portion of the log message (everything after [xml]=)
    xml_start = log_message.find('[xml]=')
    if xml_start != -1:
        # Extract the XML data
        xml_data = log_message[xml_start + 6:]  # Skip the '[xml]=' part
        try:
            # Parse the XML string
            root = ET.fromstring(xml_data)
            
            # Define the namespaces to handle
            namespaces = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Extract data from the XML, especially under <EventData><Data Name="...">...</Data></EventData>
            event_data = {}
            for data in root.findall('.//event:EventData/event:Data', namespaces):
                name = data.get('Name')
                value = data.text
                event_data[name] = value
            
            # Add event data to the dictionary
            log_dict['event_data'] = event_data
        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")
    
    return log_dict

# Example raw log message from FortiSIEM
log_message = '''2024-12-04T10:37:52Z VSCCM-INMP03.apraava.com 172.16.100.109 FSM-WUA-WinLog-Security [phCustId]="2007" [customer]="Apraava" [monitorStatus]="Success" [Locale]="en-IN" [MachineGuid]="6dca6bdd-f4f0-4a28-bb36-a1c049b42a9d" [timeZone]="+0530" [extEventRecvProto]="Windows Agent" [level]="Information" [xml]=<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>5156</EventID><Version>1</Version><Level>0</Level><Task>12810</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2024-12-04T10:37:51.971399500Z'/><EventRecordID>21960955863</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='6396'/><Channel>Security</Channel><Computer>VSCCM-INMP03.apraava.com</Computer><Security/></System><EventData><Data Name='ProcessID'>4644</Data><Data Name='Application'>\\device\\harddiskvolume5\\program files\\microsoft configuration manager\\bin\\x64\\smsexec.exe</Data><Data Name='Direction'>%%14593</Data><Data Name='SourceAddress'>172.16.100.109</Data><Data Name='SourcePort'>51912</Data><Data Name='DestAddress'>172.16.100.109</Data><Data Name='DestPort'>1433</Data><Data Name='Protocol'>6</Data><Data Name='FilterRTID'>2045181</Data><Data Name='LayerName'>%%14611</Data><Data Name='LayerRTID'>48</Data><Data Name='RemoteUserID'>S-1-0-0</Data><Data Name='RemoteMachineID'>S-1-0-0</Data></EventData></Event>'''
logtest2 = '''2024-12-04T11:15:09Z DC1.rmzcorp.com 192.168.1.45 FSM-WUA-WinLog-Security [phCustId]="2012" [customer]="RMZ" [monitorStatus]="Success" [Locale]="en-US" [MachineGuid]="3a3a667a-f123-451d-bfc1-8e39cadd9418" [timeZone]="+0530" [extEventRecvProto]="Windows Agent" [level]="Information" [xml]=<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4662</EventID><Version>0</Version><Level>0</Level><Task>14080</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2024-12-04T11:15:09.3548678Z'/><EventRecordID>40832226</EventRecordID><Correlation/><Execution ProcessID='1644' ThreadID='1940'/><Channel>Security</Channel><Computer>DC1.rmzcorp.com</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1454471165-573735546-725345543-500</Data><Data Name='SubjectUserName'>Administrator</Data><Data Name='SubjectDomainName'>RMZCORP</Data><Data Name='SubjectLogonId'>0x220267246</Data><Data Name='ObjectServer'>DS</Data><Data Name='ObjectType'>%{19195a5b-6da0-11d0-afd3-00c04fd930c9}</Data><Data Name='ObjectName'>%{14b2fe44-0ba1-4d26-ba43-1e8e9d67132c}</Data><Data Name='OperationType'>Object Access</Data><Data Name='HandleId'>0x0</Data><Data Name='AccessList'>%%7688
				</Data><Data Name='AccessMask'>0x100</Data><Data Name='Properties'>%%7688
		{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
	{19195a5b-6da0-11d0-afd3-00c04fd930c9}
</Data><Data Name='AdditionalInfo'>-</Data><Data Name='AdditionalInfo2'></Data></EventData></Event>'''


# Parse the log message
log_dict = parse_fortisiem_log(log_message)
log_dict2 = parse_fortisiem_log(logtest2)

# Print the resulting dictionary
customer = log_dict['customer']
src = log_dict['event_data']['SourceAddress']
dst = log_dict['event_data']['DestAddress']
srcport = log_dict['event_data']['SourcePort']
dstport = log_dict['event_data']['DestPort']

print("Customer Name: " + customer)
print("Source IP: " + src)
print("Destination IP: " + dst)
print("Source Port: " + srcport)
print("Destination Port: " + dstport)

# print(log_dict2)