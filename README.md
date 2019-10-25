# SnipeUpdaterPy
Windows based Snipe-IT Inventory updater

For this project I was setting out to create an agent of sorts for Snipe-IT.
Currently only tested on Dell systems running Windows 10.

The python script once turned into a .exe with pyinstaller (https://www.pyinstaller.org/) will gather system information 
and upload it to a Snipe-it server. Works for new uploads and systems that already exist in your database.

You will need to go through the code before turning it into an EXE to put in your server URL and API key. 
You will also need to modify the custom field names to match your custom fields on the server.

I am currently testing to see if it works on newer MacOS and will upload a version that works once it is complete.
