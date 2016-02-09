# gnome-keyring-import-export
A rewritten and expanded Python 3.x-variant of https://bitbucket.org/spookylukey/gnome-keyring-import-export
This variant uses libsecret service instead of gnomekeyring 

Simple script for exporting gnome2 (seahorse) keyrings,
and re-importing on another machine.

Usage:

1) Export json:

    gnome_keyring_import_export.py exportjson somefile.json


Please note - this dumps all your passwords *unencrypted*
into somefile.json

2) Export csv (lastpass.com format):

    gnome_keyring_import_export.py exportcsv somefile.csv

Tries to make educated guesses to make things turn up in the right columns.

Please note - this dumps all your passwords *unencrypted*
into somefile.csv

3) Import:

    gnome_keyring_import_export.py import somefile.json

This attempts to be intelligent about not duplicating
secrets already in the keyrings - see messages.

However, if you are moving machines, sometimes an application
name changes (e.g. "chrome-12345" -> "chrome-54321") so
you might need to do some manual fixes on somefile.json first.

Please make BACKUP copies of your existing keyring files
before importing into them, in case anything goes wrong.
They are normally found in:

~/.gnome2/keyrings
~/.local/share/keyrings


4) Export Chrome passwords to Firefox

This takes Chrome passwords stored in the Gnome keyring manager and creates a
file than can be imported by the Firefox "Password Exporter" extension:
https://addons.mozilla.org/en-US/firefox/addon/password-exporter/

    gnome_keyring_import_export.py export_chrome_to_firefox somefile.xml



