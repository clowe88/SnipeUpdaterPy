import requests, os, base64, subprocess, sys, json, time, datetime, mysql.connector
from multiprocessing import Queue

#Define all necessary variables
global getresponse, asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers, snipeid

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
    global asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers, snipeid

    try:#Gets assets information on Windows based systems. Designed for Windows 10
        asset = powershell('wmic SystemEnclosure get SMBIOSAssetTag')
        osname = powershell('(Get-WmiObject -Class win32_operatingsystem).Caption')
        manufacturer = powershell('(Get-WmiObject -Class win32_computersystem).Manufacturer')
        compname = powershell('(Get-WmiObject -Class win32_computersystem).Name')
        modelname = powershell('(Get-WmiObject -Class win32_computersystem).Model')
        ramtotal = powershell('(Get-WmiObject -Class win32_computersystem).TotalPhysicalMemory/1Gb')
        ramtotal = str(round(float(ramtotal))) + "GB"
        lastlogon = powershell('[System.Security.Principal.WindowsIdentity]::GetCurrent().Name')
        serialnum = powershell('wmic SystemEnclosure get SerialNumber')
        osver = powershell('(Get-WMIObject win32_operatingsystem).Version')
        #Check if a Wifi MAC is passed, omits entry if no valid Wifi adapter
        try:
            wifimac = powershell('(Get-Netadapter -physical Wi-Fi*).MacAddress')
        except:pass
        ethermac = powershell('(Get-Netadapter -physical Ethernet*).MacAddress')
        ipv4address = powershell('(Get-NetIpaddress -InterfaceAlias Ethernet* -AddressFamily IPv4).IPAddress')
        softwarelist = powershell("(Get-ItemProperty HKLM:/Software/Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall/* | Select-Object DisplayName).DisplayName")
        printerlist = powershell('(Get-Printer).Name')
    except:#Gathers assets information on MacOSX based systems. Designed for High Sierra or newer.
        serialnum = subprocess.getoutput("ioreg -l | grep IOPlatformSerialNumber")
        asset = serialnum
        osname = subprocess.getoutput("sw_vers -productName")
        compname = subprocess.getoutput("hostname")
        modelname = subprocess.getoutput("sysctl hw.model")
        ramtotal = subprocess.getoutput('system_profiler SHardwareDataType | grep "  Memory:"')
        ramtotal = ramtotal.replace("Memory:","").replace(" ","").replace(":","")
        lastlogon = subprocess.getoutput("id -un")
        osver = subprocess.getoutput("sw_vers -productVersion")
        try:
            wifimac = subprocess.getoutput("ifconfig en1 | awk '/ether/{print $2}'")
        except:pass
        ethermac = subprocess.getoutput("ifconfig en0 | awk '/ether/{print $2}'")
        try:
            ipv4address = subprocess.getoutput("ipconfig getifaddr en0")
        except:
            ipv4address = subprocess.getoutput("ifconfig getifaddr en1")
        softwarelist = subprocess.getoutput("ls '/Applications/'")
        printerlist = subprocess.getoutput("lpstat -p | awk '{print $2}'")
            
    #Passes list of software as an array #Not used in this implmentation
    software = []
    for line in softwarelist.split('\n'):
        software.append(line)
    software = str(software)
    software = (software.replace("[", "").replace("]", "").replace("'", ""))
    
    #Passes list of printers as array
    printers = []
    for line in printerlist.split('\n'):
        printers.append(line)
    printers = str(printers)
    printers = (printers.replace("[", "").replace("]", "").replace("'", ""))

    #Cleanup formatting in information gathering
    asset = (asset.replace('SMBIOSAssetTag','').replace("IOPlatformSerialNumber","").replace('SerialNumber', '').replace("\r", '').replace("\n", '').replace(' ', '').replace("=","").replace('"',"").replace("|",""))
    osname = (osname.replace('Microsoft ','').replace('\n',''))
    serialnum = (serialnum.replace("IOPlatformSerialNumber","").replace('SerialNumber', '').replace("\r", '').replace("\n", '').replace(' ', '').replace("=","").replace('"',"").replace("|",""))
    compname = compname.replace('\n', '')
    modelname = modelname.replace('\n', '')
    lastlogon = lastlogon.replace('\n', '')
    ipv4address = ipv4address.replace('\n','')
    ethermac = ethermac.replace('\n','')
    wifimac = wifimac.replace('\n','')
    osver = osver.replace('\n','')

def send_info():
    global getresponse, asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers, snipeid
   
    #Gather System Information
    get_info()

    #Check to see if Asset Tag is set in bios, if not it uses the serial number
    if asset == "":
        asset = serialnum
        
    #Gets the current information on assest if it exists,
    #used to get the ID field to modify the URL when updating instead of new additions
    url = "<YOUR-URI-HERE>"
    headers = {'authorization': "Bearer <YOUR-API-KEY-HERE>",
            'accept': "application/json", 
            'content-type': "application/json"
                }

    query = url + "/bytag/" + asset
    getresponse = requests.request("GET", query, headers=headers)

    #Parses the response to get just the ID number
    data = getresponse.text
    data = json.loads(data)
    try:snipeid = data["id"]
    except:snipeid = ""
    try:snipeid = int(snipeid)
    except:pass

    #Assigns the field values for uploading    
    fields = {"id":snipeid,
            "name":compname,
            "asset_tag":asset,
            "serial":serialnum,
            "model_id":1,
            "status_id":2,
            "category_id":2,
            "manufacturer_id":1,
            "deleted_at":"null",
            "_snipeit_last_login_4":lastlogon,
            "_snipeit_ip_address_5":ipv4address,
            "_snipeit_ethernet_mac_2":ethermac,
            "_snipeit_wireless_mac_3":wifimac,
            "_snipeit_os_6":osname,
            "_snipeit_os_version_7":osver,
            "_snipeit_ram_8":ramtotal,
            "_snipeit_printers_9":printers,
            "_snipeit_software_list_10":software
                }

    #Base URL of SnipeIT server
    url = "<YOUR-URI-HERE>"

    #If the asset exists, this sets the request to update(PATCH/PUT) instead of add(Put)
    if "id" in data:
        #restores Asset to allow updating
        cnx = mysql.connector.connect(user='<REMOTE-DB-USERNAME>', password="<DB-PASSWORD>",
                              host="<SERVER-IP>", 
                              database="<DATABASE-NAME>")
        cursor = cnx.cursor()

        restoreasset = ("UPDATE assets SET deleted_at=NULL WHERE id=" + str(snipeid) + ";")
        cursor.execute(restoreasset)
        cnx.commit()
        cursor.close()
        cnx.close()

        updateaction = "PATCH"
        fields["id"] = snipeid
        url = url + "/" + str(snipeid)
    else:
        updateaction = "POST"

    #Pushses the new information to the server
    headers = {'authorization': "Bearer <YOUR-API-KEY-HERE>",
            'accept': "application/json", 
            'content-type': "application/json"
                }

    payload = json.dumps(fields)
    response = requests.request(updateaction, url, data=payload, headers=headers)

    print(response.text)
    
def __main__():
    
    x = True
    
    while x == True: 
        
        send_info()
        time.sleep(21600)#21600 = 6 hours
     
__main__()
