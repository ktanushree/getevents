#! /usr/bin/env python

"""

Get CGX Events
tanushree@cloudgenix.com

"""

import pandas as pd
import json
import os
import sys
import datetime
import yaml
import json
import netaddr
import ipaddress
import argparse
import codecs
import csv
import cloudgenix
import cloudgenix_idname
import math

# bar
from progressbar import Bar, ETA, Percentage, ProgressBar


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Get Events Script'


# Process tags


SITES = "sites"
ELEMENTS = "elements"
INTERFACES = "interfaces"
WANINTERFACES = "waninterfaces"

RANGE = "RANGE"

xlate_info = ["network_directinternet_down", "network_vpnlink_down",
           "network_vpnss_unavailable", "network_vpnpeer_unreachable", "network_vpnss_mismatch",
          "network_directprivate_down", "network_vpnpeer_unavailable", "network_vpnbfd_down"]


try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None



def get_events(cgx_session, numhours, starttime, endtime, event_codes, sitelist):

    global eventsdf
    eventsdf = pd.DataFrame()

    if numhours == RANGE:
        start_time_iso = starttime.isoformat() + "Z"
        end_time_iso = endtime.isoformat() + "Z"

    else:
        current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0)
        start_time = current_time - datetime.timedelta(hours= numhours)
        start_time_iso = start_time.isoformat() + "Z"
        end_time_iso = None

    eventlist = []

    #
    # Get matching set of events.
    #

    events_query_payload = {
        "limit":
            {
                "count": 100,
                "sort_on": "time",
                "sort_order": "descending"
            },
        "query": {
            "code": event_codes,
            "site": sitelist
        },
        "severity": [],
        "start_time":start_time_iso,
        "end_time":end_time_iso
    }

    more_events=True
    while more_events:
        print ("INFO: Getting {0} starting from {1} using query {2}".format(event_codes, start_time_iso, json.dumps(events_query_payload)))
        resp = cgx_session.post.events_query(data=events_query_payload, api_version='v3.1')
        if resp.cgx_status:
            eventlist = resp.cgx_content.get("items", None)
            dp = pd.DataFrame(eventlist)

            if len(dp)>0:
                seta = set(dp.id.unique())

                if len(eventsdf) > 0:
                    setb = set(eventsdf.id.unique())

                    duplicates = list(seta & setb)
                    if duplicates:
                        print("\n\n!!!!! Duplicate event returned !!!!!")
                        print("{}\n\n".format(duplicates))
                        for id in duplicates:
                            print("Removing duplicate event {} from dp".format(id))
                            dp = dp[dp.id != id]

                        print("\n\n")

            eventsdf = pd.concat([eventsdf,dp], ignore_index=True)

            offset = resp.cgx_content['_offset']
            print ("\tTotal events: {0}. Events Retrieved: {1}. Events Pending: {2}".format(resp.cgx_content['total_count'],resp.cgx_content['included_count'], (resp.cgx_content['total_count']-resp.cgx_content['included_count']) ))

            if offset:
                events_query_payload['_offset'] = offset
                more_events = True

            else:
                more_events = False

        else:
            print ("ERR: Failed to get events: {}".format(resp.cgx_content))
            print(cloudgenix.jd_detailed(resp))

            more_events = False
            return []


    # Get Standing events:
    standingevents_query_payload = {
        "limit":
            {
                "count": 100,
                "sort_on": "time",
                "sort_order": "descending"
            },
        "query": {
            "code": event_codes,
            "site": sitelist
        },
        "severity": [],
        "start_time": None,
        "end_time": None
    }

    print("INFO: Getting standing alarms")
    more_events = True
    while more_events:
        print ("INFO: Getting {0} starting from {1} using query {2}".format(event_codes, start_time_iso,
                                                                            json.dumps(standingevents_query_payload)))
        resp = cgx_session.post.events_query(data=standingevents_query_payload)
        if resp.cgx_status:
            eventlist = resp.cgx_content.get("items", None)
            dp = pd.DataFrame(eventlist)

            if len(dp) > 0:
                seta = set(dp.id.unique())

                if len(eventsdf) > 0:
                    setb = set(eventsdf.id.unique())

                    duplicates = list(seta & setb)
                    if duplicates:
                        print("\n\n!!!!! Duplicate event returned !!!!!")
                        print("{}".format(duplicates))
                        for id in duplicates:
                            print("Removing duplicate event {} from dp".format(id))
                            dp = dp[dp.id != id]

                        print("\n\n")

            eventsdf = pd.concat([eventsdf, dp], ignore_index=True)

            offset = resp.cgx_content['_offset']
            print ("\tTotal events: {0}. Events Retrieved: {1}. Events Pending: {2}".format(
                resp.cgx_content['total_count'], resp.cgx_content['included_count'],
                (resp.cgx_content['total_count'] - resp.cgx_content['included_count'])))

            if offset:
                standingevents_query_payload['_offset'] = offset
                more_events = True

            else:
                more_events = False

        else:
            print ("ERR: Failed to get events: {}".format(resp.cgx_content))
            print(cloudgenix.jd_detailed(resp))

            more_events = False
            return []

    print("DEBUG: Saving raw events")
    rawfile = os.path.join('./', 'cgxdebug_rawevents.csv')
    eventsdf.to_csv(rawfile,index=False)

    return eventsdf



def createdicts(cgx_session):
    global elem_id_name_dict
    global site_id_name_dict
    global site_name_id_dict
    global eid_sid_dict
    global intf_id_name_dict
    global swi_id_name_dict
    global userid_username_dict
    global path_id_name_dict

    elem_id_name_dict = {}
    site_id_name_dict = {}
    site_name_id_dict = {}
    eid_sid_dict = {}
    intf_id_name_dict = {}
    swi_id_name_dict = {}
    userid_username_dict = {}
    path_id_name_dict = {}

    idname = cloudgenix_idname.CloudGenixIDName(cgx_session)

    print("INFO: Building Translation dicts")
    print("\tSites..")
    site_id_name_dict = idname.generate_sites_map()
    site_name_id_dict = idname.generate_sites_map(key_val='name',value_val='id')


    print("\tElements..")
    elem_id_name_dict = idname.generate_elements_map()
    eid_sid_dict = idname.generate_elements_map(key_val='id',value_val='site_id')

    print("\tInterfaces..")
    intf_id_name_dict = idname.generate_interfaces_map()

    print("\tSite WAN Interfaces..")
    swi_id_name_dict = idname.generate_waninterfaces_map()


    print("\tOperators..")
    resp = cgx_session.get.operators_t()
    if resp.cgx_status:
        userlist = resp.cgx_content.get("items", None)
        for user in userlist:
            username = "{} {} ({})".format(user['first_name'], user.get('last_name', None), user['email'])
            userid_username_dict[user['id']] = username
    else:
        print("ERR: Could not query for operators")
        print(cloudgenix.jd_detailed(resp))


    print("\tSecure Fabric links")

    for siteid in site_id_name_dict.keys():
        resp = cgx_session.post.topology(data={"type": "basenet", "nodes": [siteid], "links_only": True})
        if resp.cgx_status:
            links = resp.cgx_content.get("links", None)
            for path in links:
                if path["type"] in ["anynet", "public-anynet", "private-anynet"]:
                    # anynet link, get relevant names
                    source_site_name = path.get("source_site_name")
                    target_site_name = path.get("target_site_name")
                    source_wan_network = path.get("source_wan_network")
                    target_wan_network = path.get("target_wan_network")
                    source_circuit_name = path.get("source_circuit_name")
                    target_circuit_name = path.get("target_circuit_name")

                    # circuit names may be blank. Normalize.
                    if not source_circuit_name:
                        source_circuit_name = "Circuit to {0}".format(source_wan_network)
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(target_wan_network)

                    pathname = "{0} ('{1}' via '{2}') <-> ('{3}' via '{4}') {5}".format(
                        source_site_name,
                        source_wan_network,
                        source_circuit_name,
                        target_circuit_name,
                        target_wan_network,
                        target_site_name
                    )
                elif path["type"] in ["vpn"]:
                    # vpn link, get relevant names
                    source_site_name = path.get("source_site_name")
                    target_site_name = path.get("target_site_name")
                    source_wan_network = path.get("source_wan_network")
                    target_wan_network = path.get("target_wan_network")
                    source_circuit_name = path.get("source_circuit_name")
                    target_circuit_name = path.get("target_circuit_name")
                    # circuit names may be blank. Normalize.
                    if not source_circuit_name:
                        source_circuit_name = "Circuit to {0}".format(source_wan_network)
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(target_wan_network)
                    # for vpn, get element names.
                    source_node_id = path.get("source_node_id")
                    source_element_name = elem_id_name_dict[source_node_id]
                    target_node_id = path.get("target_node_id")
                    target_element_name = elem_id_name_dict[target_node_id]

                    pathname = "[{0}] : {1} ('{2}' via '{3}') <-> ('{4}' via '{5}') {6} [{7}]".format(
                        source_element_name,
                        source_site_name,
                        source_wan_network,
                        source_circuit_name,
                        target_circuit_name,
                        target_wan_network,
                        target_site_name,
                        target_element_name
                    )

                elif path["type"] in ["priv-wan-stub", "internet-stub"]:
                    # Stub (direct) links.
                    target_site_name = site_id_name_dict[path.get("target_node_id", "")]
                    if not target_site_name:
                        target_site_name = "UNKNOWN"

                    target_circuit_name = path.get("target_circuit_name")
                    network = path.get("network")
                    if not target_circuit_name:
                        target_circuit_name = "Circuit to {0}".format(network)

                    if path["type"]== "priv-wan-stub":
                        dest_name = "Direct Private WAN"
                    elif path["type"] == "internet-stub":
                        dest_name = "Direct Internet"
                    else:
                        dest_name = "UNKNOWN"

                    pathname = "{0} ('{1}' via '{2}') <-> {3}".format(
                        target_site_name,
                        network,
                        target_circuit_name,
                        dest_name
                    )
                else:
                    continue

                path_id_name_dict[path['path_id']] = pathname

    return


def get_info(alarminfo):
    if alarminfo:
        peerid = alarminfo.get("peer_site_id", None)
        anynetid = alarminfo.get("al_id",None)
        vpn_link_id = alarminfo.get("vpn_link_id",None)
        info = None
        if peerid:
            if peerid in site_id_name_dict.keys():
                peersite = site_id_name_dict[peerid]
                info = "Peer Site: {}".format(peersite)

        if anynetid:
            if anynetid in path_id_name_dict.keys():
                info = path_id_name_dict[anynetid]
            else:
                info = "Could not query anynet link {}".format(anynetid)

        if vpn_link_id:
            if vpn_link_id in path_id_name_dict.keys():
                info = path_id_name_dict[vpn_link_id]
            else:
                info = "Could not query vpn link {}".format(vpn_link_id)

        if "element_id" in alarminfo.keys():
            elemid = alarminfo.get("element_id",None)
            interfaceid = alarminfo.get("interface_id",None)
            iname = None

            if interfaceid in intf_id_name_dict.keys():
                iname = intf_id_name_dict[interfaceid]

            if iname:
                info = "Element: {}\nInterface: {}".format(elem_id_name_dict[elemid], iname)
            else:
                info = "Element: {}".format(elem_id_name_dict[elemid])

    else:
        info = "n/a"
    return info


def get_entity(entity_ref):
    entitymap = {}
    tmp = entity_ref.split('/')
    octets = len(tmp)
    i = 0
    returnval = ""
    while i < octets:
        entitymap[tmp[i]] = tmp[i + 1]
        i += 2

    for item in [SITES, ELEMENTS, INTERFACES, WANINTERFACES]:
        if item in entitymap.keys():
            if item == SITES:
                if entitymap[item] in site_id_name_dict.keys():
                    entityname = "Site: " + site_id_name_dict[entitymap[item]]
                else:
                    entityname = "Site: Unassigned"

            elif item == ELEMENTS:
                if entitymap[item] in elem_id_name_dict.keys():
                    entityname = "Element: " + elem_id_name_dict[entitymap[item]]
                else:
                    entityname = "Element: Unknown"

            elif item == INTERFACES:
                sid = entitymap[SITES]
                eid = entitymap[ELEMENTS]
                iid = entitymap[INTERFACES]
                interface = None

                if iid in intf_id_name_dict.keys():
                    interface = intf_id_name_dict[iid]
                # else:
                #     resp = cgx_session.get.interfaces(site_id=sid, element_id=eid, interface_id=iid)
                #     interface = resp.cgx_content.get("name", None)

                if interface:
                    entityname = "Interface: " + interface
                else:
                    entityname = "Interface: Unknown"

            elif item == WANINTERFACES:
                sid = entitymap[SITES]
                swiid = entitymap[WANINTERFACES]
                swi = None

                if swiid in swi_id_name_dict.keys():
                    swi = swi_id_name_dict[swiid]
                # else:
                #     resp = cgx_session.get.waninterfaces(site_id=sid, waninterface_id=swiid)
                #     swi = resp.cgx_content.get("name", None)

                if swi:
                    entityname = "WAN Interface: " + swi
                else:
                    entityname = "WAN Interface: Unknown"

            else:
                continue

            returnval += entityname + " "

        else:
            continue

    return returnval



def gettime_ms(x):
    if "." in x:
        date = datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        date = datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ")

    time_ms = date.replace(microsecond=0)
    time_ms = time_ms.isoformat() + "Z"

    return time_ms




def gettime_sms(x):
    if "." in x:
        date = datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        date = datetime.datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ")

    time_sms = date.replace(second=0, microsecond=0)
    time_sms = time_sms.isoformat() + "Z"


    return time_sms


def getsitename(elemid):

    site = "Unassigned"
    if elemid in eid_sid_dict.keys():
        sid = eid_sid_dict[elemid]
        if sid == "1":
            site = "Unassigned"
        else:
            site = site_id_name_dict[sid]

    return site


def getelemname(elemid):
    ename = elemid
    if elemid in elem_id_name_dict.keys():
        ename = elem_id_name_dict[elemid]

    return ename


def getackinfo(acknowledgementinfo):
    acknowledgement_info = "n/a"
    if acknowledgementinfo:
        if isinstance(acknowledgementinfo, float):
            return "N/A"

        if "acknowledged_by" in acknowledgementinfo.keys():
            ackuserid = acknowledgementinfo.get("acknowledged_by", None)
            acktime = acknowledgementinfo.get("acknowledgement_time", None)
            if ackuserid in userid_username_dict.keys():
                ackuser = userid_username_dict[ackuserid]
            else:
                ackuser = ackuserid

            acknowledgement_info = "User:{} Time:{}".format(ackuser, acktime)

    return acknowledgement_info



def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Event Filters
    site_group = parser.add_argument_group('Filters for events', 'The following attributes will be used to query events')
    site_group.add_argument("--eventcodes", "-EC", help="List event codes you want to query for", default=None)
    site_group.add_argument("--sitename", "-S", help="Name of the Site you want events filtered for. For multiple sites, separate names by using a comma.", default=None)
    site_group.add_argument("--hour", "-H", help="Number of hours from now you need the events queried for. Or use the keyword RANGE to provide a time range", default=3)
    site_group.add_argument("--starttime", "-ST", help="Start time in format YYYY-MM-DDTHH:MM:SSZ", default=None)
    site_group.add_argument("--endtime", "-ET", help="End time in format YYYY-MM-DDTHH:MM:SSZ", default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Check if YAML config files was provided via CLI
    ############################################################################
    eventcodes = args['eventcodes']
    numhours = args['hour']
    sitename = args['sitename']
    starttime = args['starttime']
    endtime = args['endtime']
    stime = None
    etime = None

    if eventcodes is None:
        print("WARN: No event codes listed. All events will be returned.")

    if numhours is None:
        print("ERR: Invalid number of hours.")
        sys.exit()

    if numhours == RANGE:
        if starttime is None or endtime is None:
            print("ERR: For time range, please provide both starttime and endtime in format YYYY-MM-DDTHH:MM:SSZ")
            sys.exit()

        else:
            if "." in starttime:
                stime = datetime.datetime.strptime(starttime, "%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                stime = datetime.datetime.strptime(starttime, "%Y-%m-%dT%H:%M:%SZ")

            if "." in endtime:
                etime = datetime.datetime.strptime(endtime, "%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                etime = datetime.datetime.strptime(endtime, "%Y-%m-%dT%H:%M:%SZ")

    else:
        numhours = int(numhours)
        if numhours <= 0:
            print("ERR: Invalid number of hours.")
            sys.exit()

    if sitename is None:
        print("INFO: No site filter configured. All events will be returned")

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Build Site translation dict
    ############################################################################
    createdicts(cgx_session)
    sitelist = []
    if sitename is not None:
        sitename = sitename.replace(", ",",")
        sites = sitename.split(",")

        for site in sites:
            if site in site_name_id_dict.keys():
                sitelist.append(site_name_id_dict[site])
                continue

            else:
                print("ERR: Site {} does not exist on the tenant. Please re-enter site name(s)".format(site))
                sys.exit()

    ############################################################################
    # Get Events
    ############################################################################
    event_codes = []
    if eventcodes:
        eventcodes = eventcodes.replace(" ","")
        event_codes = eventcodes.split(",")

    events = get_events(cgx_session, numhours, stime, etime, event_codes, sitelist)
    if len(events) == 0:
        print("WARN: No events retrieved")
        print("Logging out")
        cgx_session.get.logout()
        sys.exit()

    #events = events.fillna("n/a")
    events['time_ms'] = events['time'].apply(gettime_ms)
    events['time_sms'] = events['time'].apply(gettime_sms)
    events['entity_ref_text'] = events['entity_ref'].apply(get_entity)
    events['info_text'] = events['info'].apply(get_info)
    events['site'] = events['element_id'].apply(getsitename)
    events['element'] = events['element_id'].apply(getelemname)
    events['acknowledgement_info'] = events['acknowledgement_info'].apply(getackinfo)
    events = events.drop(columns=["_etag","_created_on_utc","_updated_on_utc"])

    ############################################################################
    # Write to CSV
    ############################################################################
    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filenames
    csvfile = os.path.join('./', '%s_events_%s.csv' %(tenant_str, curtime_str))
    print("INFO: Writing events to file {}".format(csvfile))

    events.to_csv(csvfile, index=False)
    rawfile = os.path.join('./', 'cgxdebug_rawevents.csv')
    if os.path.exists(rawfile):
        print("DEBUG: Deleting raw events")
        os.remove(rawfile)

    ############################################################################
    # Logout and exit script
    ############################################################################
    print("INFO: Logging out.")
    cgx_session.get.logout()

    return



if __name__ == "__main__":
    go()
