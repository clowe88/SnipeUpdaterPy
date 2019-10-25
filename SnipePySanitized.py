import requests, os, base64, subprocess, sys, json
from multiprocessing import Queue

#Define all necessary variables
global getresponse, asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers

#Base URL of SnipeIT server
url = "<Your-URL-Here>"

#Allows for simplified code when gathering system information
def powershell(cmd, input=None):
    cmd64 = base64.encodebytes(cmd.encode('utf-16-le')).decode('ascii').strip()
    stdin = None if input is None else subprocess.PIPE
    process = subprocess.Popen(["powershell.exe", "-NonInteractive", "-EncodedCommand", cmd64], stdin=stdin, stdout=subprocess.PIPE)
    if input is not None:
        input = input.encode(sys.stdout.encoding)
    output, stderr = process.communicate(input)
    output = output.decode(sys.stdout.encoding).replace('\r\n', '\n')
    return output

#Gathers the necessary information for uploading
def get_info():
    global asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers

    asset = powershell('wmic SystemEnclosure get SMBIOSAssetTag')
    osname = powershell('(Get-WmiObject -Class win32_operatingsystem).Caption')
    manufacturer = powershell('(Get-WmiObject -Class win32_computersystem).Manufacturer')
    compname = powershell('(Get-WmiObject -Class win32_computersystem).Name')
    modelname = powershell('(Get-WmiObject -Class win32_computersystem).Model')
    ramtotal = powershell('(Get-WmiObject -Class win32_computersystem).TotalPhysicalMemory/1Gb')
    lastlogon = powershell('(Get-WmiObject -Class Win32_NetworkLoginProfile | Sort-Object -Property LastLogon -Descending | Select-Object -Property * -First 1 | Where-Object {$_.LastLogon -match "(\d{14})"} | Foreach-Object { New-Object PSObject -Property @{ Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}).Name')
    serialnum = powershell('wmic SystemEnclosure get SerialNumber')
    osver = powershell('(Get-WMIObject win32_operatingsystem).Version')
    #Check if a Wifi MAC is passed, omits entry if no valid Wifi adapter
    try:
        wifimac = powershell('(Get-Netadapter -physical Wi-Fi*).MacAddress')
    except:pass
    ethermac = powershell('(Get-Netadapter -physical Ethernet).MacAddress')
    ipv4address = powershell('(Get-NetIpaddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress')
    softwarelist = powershell("(Get-ItemProperty HKLM:/Software/Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall/* | Select-Object DisplayName).DisplayName")
    printerlist = powershell('(Get-Printer).Name')

    #Passes list of software as an array #Not used in this implmentation
    software = []
    for line in softwarelist.split('\n'):
        software.append(line)
    
    #Passes list of printers as array
    printers = []
    for line in printerlist.split('\n'):
        printers.append(line)
        
    #Cleanup formatting in information gathering
    asset = (asset.replace('SMBIOSAssetTag','').replace("\r", '').replace("\n", '').replace(' ', ''))
    osname = (osname.replace('Microsoft ','').replace('\n',''))
    ramtotal = str(round(float(ramtotal))) + "GB"
    serialnum = (serialnum.replace('SerialNumber', '').replace("\r", '').replace("\n", '').replace(' ', ''))
    compname = compname.replace('\n', '')
    modelname = modelname.replace('\n', '')
    lastlogon = lastlogon.replace('\n', '')
    ipv4address = ipv4address.replace('\n','')
    ethermac = ethermac.replace('\n','')
    wifimac = wifimac.replace('\n','')
    osver = osver.replace('\n','')
    printers = str(printers)
     
#Gather System Information
get_info()

#Check to see if Asset Tag is set in bios, if not it uses the serial number
if asset == "":
    asset = serialnum
    

#Gets the current information on assest if it exists,
#used to get the ID field to modify the URL when updating instead of new additions
headers = {'authorization': "Bearer <Your-API-Key-Here>",
           'accept': "application/json", 
           'content-type': "application/json"
            }

getresponse = requests.request("GET", url, data=asset, headers=headers)

#Parses the response to get just the ID number
data = getresponse.text.split(',')
snipeid = data[1].replace('rows', '').replace("id", '').replace('"', '').replace(":", '').replace("[", '').replace("{",'')
snipeid = int(snipeid)

#Assigns the field values for uploading, Will need to update field names to match
fields = {"id":"",
          "name":compname,
          "asset_tag":asset,
          "serial":serialnum,
          "model_id":1,
          "status_id":2,
          "category_id":2,
          "manufacturer_id":1,
          "_snipeit_last_login_4":lastlogon,
          "_snipeit_ip_address_5":ipv4address,
          "_snipeit_ethernet_mac_2":ethermac,
          "_snipeit_wireless_mac_3":wifimac,
          "_snipeit_os_6":osname,
          "_snipeit_os_version_7":osver,
          "_snipeit_ram_8":ramtotal,
          "_snipeit_printers_9":printers
            }

#If the asset exists, this sets the request to update(Patch) instead of add(Put)
if snipeid != '':
    updateaction = "PATCH"
    fields["id"] = snipeid
    url = url + "/" + str(snipeid)
else:
    updateaction = "PUT"

#Pushses the new information to the server
headers = {'authorization': "Bearer <Your-API-Key-Here>",
           'accept': "application/json", 
           'content-type': "application/json"
            }

payload = json.dumps(fields)
response = requests.request(updateaction, url, data=payload, headers=headers)

print(response.text)