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

# bar
from progressbar import Bar, ETA, Percentage, ProgressBar


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Get Events Script'


# Process tags
elem_id_name_dict = {}
site_id_name_dict = {}
site_name_id_dict = {}
eid_sid_dict = {}
intf_id_name_dict = {}
intf_name_id_dict = {}
swi_id_name_dict = {}
swi_name_id_dict = {}


SITES = "sites"
ELEMENTS = "elements"
INTERFACES = "interfaces"
WANINTERFACES = "waninterfaces"

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



def get_events(cgx_session, numhours, event_codes, sitelist):

    current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0)
    start_time = current_time - datetime.timedelta(hours= numhours)
    start_time_iso = start_time.isoformat() + "Z"

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
        "start_time":start_time_iso
    }

    more_events=True
    while more_events:
        print ("INFO: Getting {0} starting from {1} using query {2}".format(event_codes, start_time_iso, json.dumps(events_query_payload)))
        resp = cgx_session.post.events_query(data=events_query_payload)
        if resp.cgx_status:
            eventlist += resp.cgx_content.get("items", None)
            offset = resp.cgx_content['_offset']
            print ("\tTotal events: {0}. Events Retrieved: {1}. Events Pending: {2}".format(resp.cgx_content['total_count'],resp.cgx_content['included_count'], (resp.cgx_content['total_count']-resp.cgx_content['included_count']) ))

            if offset:
                events_query_payload['start_time'] = start_time_iso
                events_query_payload['_offset'] = offset
                more_events = True

            else:
                more_events = False

        else:
            print ("ERR: Failed to get events: {}".format(resp.cgx_content))
            print(cloudgenix.jd_detailed(resp))

            more_events = False
            return []

    #print "\t{0}:{1} returned".format(datetime.datetime.utcnow(), len(eventlist))
    return eventlist



def createdicts(cgx_session):
    print("INFO: Building Translation dicts")
    print("\tSites..")
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items", None)

        for site in sitelist:
            sid = site['id']
            sname = site['name']
            site_id_name_dict[sid] = sname
            site_name_id_dict[sname] = sid

    else:
        print "ERR: Could not get sites"
        print cloudgenix.jd_detailed(resp)


    print("\tElements..")
    resp = cgx_session.get.elements()
    if resp.cgx_status:
        elemlist = resp.cgx_content.get("items", None)

        for elem in elemlist:
            eid = elem['id']
            ename = elem['name']
            if ename is None:
                ename = elem['serial_number']

            elem_id_name_dict[eid] = ename

            sid = elem['site_id']
            eid_sid_dict[eid] = sid


    print("\tInterfaces..")
    for eid in eid_sid_dict.keys():
        sid = eid_sid_dict[eid]
        if sid == "1":
            continue

        resp = cgx_session.get.interfaces(site_id=sid, element_id=eid)
        if resp.cgx_status:
            intflist = resp.cgx_content.get("items",None)

            for intf in intflist:
                iid = intf['id']
                iname = intf['name']

                intf_id_name_dict[(sid,eid,iid)] = iname
                intf_name_id_dict[(sid,eid,iname)] = iid

        else:
            print("ERR: Could not query for interfaces")
            print(cloudgenix.jd_detailed(resp))

    print("\tSite WAN Interfaces..")
    for sid in site_id_name_dict.keys():
        resp = cgx_session.get.waninterfaces(site_id = sid)
        if resp.cgx_status:
            swilist = resp.cgx_content.get("items", None)

            for swi in swilist:
                swiid = swi['id']
                swiname = swi['name']

                swi_id_name_dict[(sid,swiid)] = swiname
                swi_name_id_dict[(sid,swiname)] = swiid
        else:
            print("ERR: Could not query for site wan interfaces")
            print(cloudgenix.jd_detailed(resp))

    return


def get_info(cgx_session, alarm):
    info = alarm['info']
    if alarm['code'].lower() in xlate_info:
        if "VPN" in alarm['code']:
            if alarm['code'].lower() == "network_vpnpeer_unavailable":
                peerid = info['peer_site_id']
                if peerid in site_id_name_dict.keys():
                    peersite = site_id_name_dict[peerid]
                    info = "Peer Site: {}".format(peersite)
            else:
                anynetid = info['al_id']
                resp = cgx_session.get.anynetlinks_t(anynetlink_id=anynetid)
                if resp.cgx_status:
                    vpndata = resp.cgx_content

                    #
                    # TO DO: Update info to include circuit names once CGB-14459 is resolved
                    #
                    info = "{}({}) <-> ({}){}".format(vpndata['source_site_name'], vpndata['source_wan_network'],
                                                      vpndata['target_wan_network'], vpndata['target_site_name'])

                else:
                    info = "Could not query anynet link {}".format(anynetid)
        else:
            elemid = info['element_id']
            interfaceid = info['interface_id']
            siteid = alarm['site_id']

            if (siteid,elemid,interfaceid) in intf_id_name_dict.keys():
                iname = intf_id_name_dict[(siteid,elemid,interfaceid)]
            else:
                resp = cgx_session.get.interfaces(site_id=siteid, element_id=elemid, interface_id=interfaceid)
                if resp.cgx_status:
                    iname = resp.cgx_content.get("name",None)

            if iname:
                info = "Element: {}\nInterface: {}".format(elem_id_name_dict[elemid], iname)
            else:
                info = "Element: {}".format(elem_id_name_dict[elemid])

    return info


def get_entity(cgx_session, alarm):
    entitymap = {}
    entity_ref = alarm['entity_ref']
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

                if (sid,eid,iid) in intf_id_name_dict.keys():
                    interface = intf_id_name_dict[(sid,eid,iid)]
                else:
                    resp = cgx_session.get.interfaces(site_id=sid, element_id=eid, interface_id=iid)
                    interface = resp.cgx_content.get("name", None)

                if interface:
                    entityname = "Interface: " + interface
                else:
                    entityname = "Interface: Unknown"

            elif item == WANINTERFACES:
                sid = entitymap[SITES]
                swiid = entitymap[WANINTERFACES]

                if (sid,swiid) in swi_id_name_dict.keys():
                    swi = swi_id_name_dict[(sid,swiid)]
                else:
                    resp = cgx_session.get.waninterfaces(site_id=sid, waninterface_id=swiid)
                    swi = resp.cgx_content.get("name", None)

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

    # Commandline for entering Site info
    site_group = parser.add_argument_group('Filters for events', 'The following attributes will be used to query events')
    site_group.add_argument("--eventcodes", "-EC", help="List event codes you want to query for", default=None)
    site_group.add_argument("--hour", "-H", help="Number of hours from now you need the events queried for", default=None)
    site_group.add_argument("--sitename", "-S", help="Name of the Site you want events filtered for. For multiple sites, separate names by using a comma.", default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Check if YAML config files was provided via CLI
    ############################################################################
    eventcodes = args['eventcodes']
    numhours = int(args['hour'])
    sitename = args['sitename']

    if eventcodes is None:
        print("WARN: No event codes listed. All events will be returned.")

    if numhours is None or numhours <= 0:
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

    events = get_events(cgx_session, numhours, event_codes, sitelist)

    ############################################################################
    # Write to CSV
    ############################################################################
    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filenames
    csvfile = os.path.join('./', '%s_events_%s.csv' %(tenant_str, curtime_str))
    with open(csvfile, 'w') as csv_file:
        csv_file.write('Element,Serial Number,Site\n')
        csv_file.flush()

    csvdata = pd.DataFrame(columns=["time","code","id","severity","type","correlation_id","site","element","entity_ref","entity_ref text","info","info text","cleared","acknowledged","acknowledgement_info"])
    print("INFO: Creating pandas dict")

    firstbar = len(events) + 1
    barcount = 1

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    for event in events:
        cleared = "n/a"
        correlation_id = "n/a"
        site = "Unassigned"

        entity_ref = get_entity(cgx_session, event)
        info = get_info(cgx_session, event)

        if event['element_id'] in eid_sid_dict.keys():
            sid = eid_sid_dict[event['element_id']]
            site = site_id_name_dict[sid]

        if event['type'] == "alarm":
            cleared = event['cleared']
            correlation_id = event['correlation_id']

        csvdata = csvdata.append({"time":event['time'],
                                  "code":event['code'],
                                  "id":event['id'],
                                  "severity":event['severity'],
                                  "type":event['type'],
                                  "correlation_id":correlation_id,
                                  "site":site,
                                  "element":elem_id_name_dict[event['element_id']],
                                  "entity_ref":event['entity_ref'],
                                  "entity_ref text":entity_ref,
                                  "info":event['info'],
                                  "info text":info,
                                  "cleared":cleared,
                                  "acknowledged":event['acknowledged'],
                                  "acknowledgement_info":event['acknowledgement_info']},ignore_index=True)

        barcount += 1
        pbar.update(barcount)


    # finish after iteration.
    pbar.finish()

    print("INFO: Writing events to file {}".format(csvfile))
    csvdata.to_csv(csvfile, index=False)


    ############################################################################
    # Logout and exit script
    ############################################################################
    print("INFO: Logging out.")
    cgx_session.get.logout()

    return



if __name__ == "__main__":
    go()