import requests, os, base64, subprocess, sys, json
from multiprocessing import Queue

#Define all necessary variables
global getresponse, asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers

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

    try:
        asset = powershell('wmic SystemEnclosure get SMBIOSAssetTag')
        osname = powershell('(Get-WmiObject -Class win32_operatingsystem).Caption')
        manufacturer = powershell('(Get-WmiObject -Class win32_computersystem).Manufacturer')
        compname = powershell('(Get-WmiObject -Class win32_computersystem).Name')
        modelname = powershell('(Get-WmiObject -Class win32_computersystem).Model')
        ramtotal = powershell('(Get-WmiObject -Class win32_computersystem).TotalPhysicalMemory/1Gb')
        ramtotal = str(round(float(ramtotal))) + "GB"
        lastlogon = powershell('(Get-WmiObject -Class Win32_NetworkLoginProfile | Sort-Object -Property LastLogon -Descending | Select-Object -Property * -First 1 | Where-Object {$_.LastLogon -match "(\d{14})"} | Foreach-Object { New-Object PSObject -Property @{ Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}).Name')
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
    except:
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
        printers.append(line.replace('\\\\vetprint\\', ''))
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

def __main__():
    global getresponse, asset, osname, ramtotal, serialnum, compname, modelname, lastlogon, osver, wifimac, ethermac, ipv4address, software, printers
   
    #Gather System Information
    get_info()

    #Check to see if Asset Tag is set in bios, if not it uses the serial number
    if asset == "":
        asset = serialnum
        
    #Gets the current information on assest if it exists,
    #used to get the ID field to modify the URL when updating instead of new additions
    url = "https://vetmed19.vetmed.vt.edu/api/v1/hardware"
    headers = {'authorization': "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjBmNGQ5YzE2ZTljOWZkMjM4NjNjZTQyNGY4NmZlYWU4NTExODc3YTY2N2QwZGIyMjQ0MDhiY2UzNjFkOGY0OTJiZjI0MTgxZDA4NzQ3MWQ2In0.eyJhdWQiOiIxIiwianRpIjoiMGY0ZDljMTZlOWM5ZmQyMzg2M2NlNDI0Zjg2ZmVhZTg1MTE4NzdhNjY3ZDBkYjIyNDQwOGJjZTM2MWQ4ZjQ5MmJmMjQxODFkMDg3NDcxZDYiLCJpYXQiOjE1NzE3NjgwMjYsIm5iZiI6MTU3MTc2ODAyNiwiZXhwIjoxNjAzMzkwNDI2LCJzdWIiOiIxIiwic2NvcGVzIjpbXX0.kc90od4ggs0bceMD7JQwUk3dz4ZPgafVv-ycV0t5mXUkCWalyIJWLettN62fibMbMKNnpY-dy204jWKPnklys55pIp_yRIzlSQc50gdm3YPqgW8TDfTCGU1B8tgjyllNeULXXDpgoI9MnqlhfjmSS1ZWGWQaK6XNPGRwASMfYsR8Do72cjLwxhIJdAQO0jsmbJvvPRxF5pZhfjmVthWJNJWF0hvXcRq_Z8hDggqNOBJucOjxnvuxojBMnWvb7OxEg2KsL9oO7Za9_FHzRvwdP2JN4dVnBCdi0widtHJ8zs4DgQ6YJLQ0Uui7JfbuKvq2Vhbl4L8LGDwKuWnAT8f7bBe79_LVxnDWfGw5OHem2OxFWAg6yh1GKIGCsCTQMggY8Qo2nDXdARt6WX_ga4o9S5fZppSjqkRtcf-3u1_doR6Lzz7TtTGo6b_NmiztwuR7BqNNOW5X_F0VOaVz-zp0c9Vuaicyyscv2uyAF9N38EyWUQuih7F2abGNzaAgERrxJLGc4YUzrcJl9_K_zZ943tOpT93bU1ds4JOKNSewrLEj5R62FbOn_KzEk8rBSruJb_vi_57GJq6DPZuWwIWc965T7Nroz0b8YxOnaSahKFhcX4pR-q1WOc4l3FDz2dr-oSc4L3Pr56czvi2mgbSod9ykaiwIquX5xYjSQT7BFII",
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
    url = "https://vetmed19.vetmed.vt.edu/api/v1/hardware"

    #If the asset exists, this sets the request to update(PATCH/PUT) instead of add(Put)
    if len(data) > 3 and data["deleted_at"] == None or len(data) > 3 and data["deleted_at"] != None:
        updateaction = "PATCH"
        fields["id"] = snipeid
        url = url + "/" + str(snipeid)
    else:
        updateaction = "POST"

    #Pushses the new information to the server
    headers = {'authorization': "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjBmNGQ5YzE2ZTljOWZkMjM4NjNjZTQyNGY4NmZlYWU4NTExODc3YTY2N2QwZGIyMjQ0MDhiY2UzNjFkOGY0OTJiZjI0MTgxZDA4NzQ3MWQ2In0.eyJhdWQiOiIxIiwianRpIjoiMGY0ZDljMTZlOWM5ZmQyMzg2M2NlNDI0Zjg2ZmVhZTg1MTE4NzdhNjY3ZDBkYjIyNDQwOGJjZTM2MWQ4ZjQ5MmJmMjQxODFkMDg3NDcxZDYiLCJpYXQiOjE1NzE3NjgwMjYsIm5iZiI6MTU3MTc2ODAyNiwiZXhwIjoxNjAzMzkwNDI2LCJzdWIiOiIxIiwic2NvcGVzIjpbXX0.kc90od4ggs0bceMD7JQwUk3dz4ZPgafVv-ycV0t5mXUkCWalyIJWLettN62fibMbMKNnpY-dy204jWKPnklys55pIp_yRIzlSQc50gdm3YPqgW8TDfTCGU1B8tgjyllNeULXXDpgoI9MnqlhfjmSS1ZWGWQaK6XNPGRwASMfYsR8Do72cjLwxhIJdAQO0jsmbJvvPRxF5pZhfjmVthWJNJWF0hvXcRq_Z8hDggqNOBJucOjxnvuxojBMnWvb7OxEg2KsL9oO7Za9_FHzRvwdP2JN4dVnBCdi0widtHJ8zs4DgQ6YJLQ0Uui7JfbuKvq2Vhbl4L8LGDwKuWnAT8f7bBe79_LVxnDWfGw5OHem2OxFWAg6yh1GKIGCsCTQMggY8Qo2nDXdARt6WX_ga4o9S5fZppSjqkRtcf-3u1_doR6Lzz7TtTGo6b_NmiztwuR7BqNNOW5X_F0VOaVz-zp0c9Vuaicyyscv2uyAF9N38EyWUQuih7F2abGNzaAgERrxJLGc4YUzrcJl9_K_zZ943tOpT93bU1ds4JOKNSewrLEj5R62FbOn_KzEk8rBSruJb_vi_57GJq6DPZuWwIWc965T7Nroz0b8YxOnaSahKFhcX4pR-q1WOc4l3FDz2dr-oSc4L3Pr56czvi2mgbSod9ykaiwIquX5xYjSQT7BFII",
            'accept': "application/json", 
            'content-type': "application/json"
                }

    payload = json.dumps(fields)
    response = requests.request(updateaction, url, data=payload, headers=headers)

    print(response.text)
    
__main__()