#!/usr/bin/env python

# Simple script for exporting gnome2 (seahorse) keyrings,
# and re-importing on another machine.

# Usage:
#
# 1) Export:
#
#   gnome_keyring_import_export.py export somefile.json
#
#
# Please note - this dumps all your passwords *unencrypted*
# into somefile.json
#
# 2) Import:
#
#   gnome_keyring_import_export.py import somefile.json
#
# This attempts to be intelligent about not duplicating
# secrets already in the keyrings - see messages.
#
# However, if you are moving machines, sometimes an application
# name changes (e.g. "chrome-12345" -> "chrome-54321") so
# you might need to do some manual fixes on somefile.json first.
#
# Please make BACKUP copies of your existing keyring files
# before importing into them, in case anything goes wrong.
# They are normally found in:
#
#  ~/.gnome2/keyrings
#  ~/.local/share/keyrings
#
#
# 3) Export Chrome passwords to Firefox
#
# This takes Chrome passwords stored in the Gnome keyring manager and creates a
# file than can be imported by the Firefox "Password Exporter" extension:
# https://addons.mozilla.org/en-US/firefox/addon/password-exporter/
#
#   gnome_keyring_import_export.py export_chrome_to_firefox somefile.xml
#



import json
import sys
import urllib.parse

import lxml.etree
import ctypes

from lxml.etree import Element
import keyring
from gi.repository import Gtk
from gi.repository import GnomeKeyring
from gi.repository.GLib import Array
from gi.repository import Secret

def mk_copy(item):
    c = item.copy()
    c['attributes'] = c['attributes'].copy()
    return c

def remove_insignificant_data(item, ignore_secret=False):
    item.pop('mtime', None)
    item.pop('ctime', None)
    item.pop('mtime', None)
    item['attributes'].pop('date_created', None)
    if ignore_secret:
        item.pop('secret', None)

def items_roughly_equal(item1, item2, ignore_secret=False):
    c1 = mk_copy(item1)
    c2 = mk_copy(item2)

    remove_insignificant_data(c1, ignore_secret=ignore_secret)
    remove_insignificant_data(c2, ignore_secret=ignore_secret)

    return c1 == c2

def findfirstfield(_order, _item):
    for _curr_field in _order:
        if isinstance(_curr_field, list):
            _curr_level = _item
            for _curr_part in _curr_field:
                if _curr_part in _curr_level:
                    _curr_level = _curr_level[_curr_part]
                    continue
                else:
                    _curr_level = None
                    break
            if _curr_level:
                return _curr_level
        else:
            if _curr_field in _item:
                return _item[_curr_field]
    return ""



def export_keyrings_csv(to_file):
    _collections = get_gnome_keyrings()
    _output = "url,type,username,password,hostname,extra,name,folder\n"
    for _curr_collection in _collections.values():
        for _item in _curr_collection:
            if _item["secret"] != "":
                if _item["schema_name"] == "chrome_libsecret_password_schema":
                    _output += ",".join([findfirstfield([["attributes","action_url"], "label"], _item),
                                         _item["schema_name"],
                                         findfirstfield([["attributes","username_value"], ["attributes","account"]], _item),
                                         _item["secret"],
                                         _item["attributes"]["signon_realm"],
                                         _item["display_name"],
                                         _item["label"],
                                         ""]
                                        ) + "\n"
                elif _item["schema_name"] == "org.freedesktop.Secret.Generic" and \
                                findfirstfield([["attributes","username_value"], ["attributes","account"]], _item) != "":

                    # url,type,username,password,hostname,extra,name,folder
                    _output += ",".join([findfirstfield([["attributes","signon_realm"], ["attributes","service"], "label"], _item),
                                         _item["schema_name"],
                                         findfirstfield([["attributes","username_value"], ["attributes","account"]], _item),
                                         _item["secret"],
                                         findfirstfield(["signon_realm"], _item),
                                         _item["display_name"],
                                         _item["label"],
                                         ""]
                                        ) + "\n"

                elif _item["schema_name"] == "org.gnome.keyring.Note":
                    # url,type,username,password,hostname,extra,name,folder
                    _output += ",".join(["http://sn",
                                         _item["schema_name"],
                                         _item["label"].split(" ")[-1],
                                         _item["secret"],
                                         "",
                                         "",
                                         _item["label"],
                                         ""]
                                        ) + "\n"
                elif _item["schema_name"] == "org.gnome.keyring.NetworkPassword":
                    # url,type,username,password,hostname,extra,name,folder
                    _output += ",".join(["http://sn",
                                         _item["schema_name"],
                                         findfirstfield([["attributes","user"]], _item),
                                         _item["secret"],
                                         findfirstfield(["server"], _item),
                                         findfirstfield([["attributes","domain"], ["attributes", "server"]], _item),
                                         _item["label"],
                                         ""]
                                        ) + "\n"
    with open(to_file, "w") as f:
        f.write(_output)

def export_keyrings_json(to_file):
    with open(to_file, "w") as f:
        f.write(json.dumps(get_gnome_keyrings(), indent=2))

def export_keyrings_to_lastpass(to_file):
    for _curr_ring in get_gnome_keyrings():
        pass
    with open(to_file, "w") as f:
        f.write(json.dumps(get_gnome_keyrings(), indent=2))

def get_item(item):
    item.load_secret_sync()
    return {
        'display_name': item.get_name(),
        'owner_name': item.get_name_owner(),
        'label': item.get_label(),
        'secret': item.get_secret().get_text(),
        'mtime': item.get_modified(),
        'ctime': item.get_created(),
        'attributes': item.get_attributes(),
        "schema_name": item.get_schema_name()
        }


def get_gnome_keyrings():
    _keyrings = {}
    _service = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS)
    _service.unlock_sync([_service])
    for _collection in _service.get_collections():

        _collection_name = _collection.get_name()
        _keyring_items = []
        _keyrings[_collection_name] = _keyring_items

        for _item in _collection.get_items():
            if _item is not None:
                _keyring_items.append(get_item(_item)  )

        print(_collection_name + "\n" + str(_keyring_items))

    print(str(_keyrings))
    return _keyrings

def export_chrome_to_firefox(to_file):
    """
    Finds Google Chrome passwords and exports them to an XML file that can be
    imported by the Firefox extension "Password Exporter"
    """
    keyrings = get_gnome_keyrings()
    items = []
    item_set = set()
    for keyring_name, keyring_items in list(keyrings.items()):
        for item in keyring_items:
            if (not item['display_name'].startswith('http')
                and not item['attributes'].get('application', '').startswith('chrome')):
                continue
            items.append(item)

            attribs = item['attributes']
            item_def = (attribs['signon_realm'],
                        attribs['username_value'],
                        attribs['action_url'],
                        attribs['username_element'],
                        attribs['password_element'],
                        )
            if item_def in item_set:
                sys.stderr.write("Warning: duplicate found for %r\n\n" % (item_def,))
            item_set.add(item_def)

    xml = items_to_firefox_xml(items)
    with open(to_file, "w") as f:
        f.write(str(xml, encoding="utf-8"))

def items_to_firefox_xml(items):
    doc = Element('xml')
    entries = Element('entries',
                      dict(ext="Password Exporter", extxmlversion="1.1", type="saved", encrypt="false"))
    doc.append(entries)
    for item in items:
        attribs = item['attributes']
        url = urllib.parse.urlparse(attribs['signon_realm'])
        entries.append(Element('entry',
                               dict(host=url.scheme + "://" + url.netloc,
                                    user=attribs['username_value'],
                                    password=item['secret'],
                                    formSubmitURL=attribs['action_url'],
                                    httpRealm=url.path.lstrip('/'),
                                    userFieldName=attribs['username_element'],
                                    passFieldName=attribs['password_element'],
                                    )))
    return lxml.etree.tostring(doc, pretty_print=True)


def fix_attributes(d):
    return {str(k): str(v) if isinstance(v, str) else v for k, v in list(d.items())}


def import_keyrings(from_file):
    with open(from_file, "r") as f:
        keyrings = json.loads(f)

    for keyring_name, keyring_items in list(keyrings.items()):
        try:
            existing_ids = GnomeKeyring.list_item_ids_sync(keyring_name)
        except GnomeKeyring.NoSuchKeyringError:
            sys.stderr.write("No keyring '%s' found. Please create this keyring first" % keyring_name)
            sys.exit(1)

        existing_items = [get_item(keyring_name, id) for id in existing_ids]
        existing_items = [i for i in existing_items if i is not None]

        for item in keyring_items:
            if any(items_roughly_equal(item, i) for i in existing_items):
                print("Skipping %s because it already exists" % item['display_name'])
            else:
                nearly = [i for i in existing_items if items_roughly_equal(i, item, ignore_secret=True)]
                if nearly:
                    print("Existing secrets found for '%s'" % item['display_name'])
                    for i in nearly:
                        print(" " + i['secret'])

                    print("So skipping value from '%s':" % from_file)
                    print(" " + item['secret'])
                else:
                    schema = item['attributes']['xdg:schema']
                    item_type = None
                    if schema ==  'org.freedesktop.Secret.Generic':
                        item_type = GnomeKeyring.ITEM_GENERIC_SECRET
                    elif schema == 'org.gnome.keyring.Note':
                        item_type = GnomeKeyring.ITEM_NOTE
                    elif schema == 'org.gnome.keyring.NetworkPassword':
                        item_type == GnomeKeyring.ITEM_NETWORK_PASSWORD

                    if item_type is not None:
                        item_id = GnomeKeyring.item_create_sync(keyring_name,
                                                                item_type,
                                                                item['display_name'],
                                                                fix_attributes(item['attributes']),
                                                                item['secret'],
                                                                False)
                        print("Copying secret %s" % item['display_name'])
                    else:
                        print("Can't handle secret '%s' of type '%s', skipping" % (item['display_name'], schema))


if __name__ == '__main__':
    if len(sys.argv) == 3:
        if sys.argv[1] == "exportjson":
            export_keyrings_json(sys.argv[2])
        if sys.argv[1] == "exportcsv":
            export_keyrings_csv(sys.argv[2])
        if sys.argv[1] == "import":
            import_keyrings(sys.argv[2])
        if sys.argv[1] == "export_chrome_to_firefox":
            export_chrome_to_firefox(sys.argv[2])

    else:
        print("See source code for usage instructions")
        sys.exit(1)
