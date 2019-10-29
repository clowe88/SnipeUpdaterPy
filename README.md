# SnipeUpdaterPy
Windows based Snipe-IT Inventory updater

For this project I am setting out to create an agent of sorts for Snipe-IT (https://snipeitapp.com/).
Currently only tested on Dell systems running Windows 10 and Macs with Mojave or newer.

The script was created using Python 3.8. Once turned into a .exe with cx_freeze (https://cx-freeze.readthedocs.io/en/latest/), using the "pip3 install cx_freeze" command to install and the "python3 setup.py bdist_dmg" command to create executables for both Windows and MacOS, it will gather system information and upload it to a Snipe-it server. Works for new uploads and systems that already exist in your database, as well as, systems that have been deleted but not purged. For the Windows executables you can also use pyinstaller (https://www.pyinstaller.org/), but the --windowed option will likely break the program.

You will need to go through the code before turning it into an EXE or DMG to put in your server URL and API key. 
You will also need to modify the custom field names to match your custom fields on the server.

The SnipePySanitized.py should work on both Windows and Mac or any system that has powershell. May need some tweaks to account for different manufacturers labels in their software. If anyone has any tweaks, improvements, or comments they would be greatly appreciated as this is my first true project of any mention.
