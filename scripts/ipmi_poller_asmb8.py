import requests
import json
import argparse
import urllib3
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class poller:
    def fixJSON(self, update):

        update = update.replace("//Dynamic Data Begin", "{")
        update = update.replace("WEBVAR_JSONVAR_WEB_SESSION =", '"WEBVAR_JSONVAR_WEB_SESSION" :')
        update = update.replace("WEBVAR_STRUCTNAME_WEB_SESSION", '"WEBVAR_STRUCTNAME_WEB_SESSION"')
        update = update.replace(
            "WEBVAR_JSONVAR_HL_GETALLSENSORS =", '"WEBVAR_JSONVAR_HL_GETALLSENSORS" :'
        )
        update = update.replace(
            "WEBVAR_STRUCTNAME_HL_GETALLSENSORS", '"WEBVAR_STRUCTNAME_HL_GETALLSENSORS"'
        )
        update = update.replace("HAPI_STATUS", '"HAPI_STATUS"')
        update = update.replace("//Dynamic data end", "}")
        update = update.replace("'", '"')
        update = update.replace(";", "")
        update = update.replace(",  {} ", "")
        update = update.split("\n", 26)[-1]

        return update

    def TypeResolve(self, sType):

        sensorType = {
            1: "temperature",
            2: "voltage",
            3: "current",
            4: "fanspeed",
            5: "chassis",
            7: "processor",
            8: "psu",
            13: "driveslotbay",
            12: "memory",
            197: "oem",
            35: "watchdog2",
            192: "temperature",
            220: "supported",
        }

        return sensorType[sType]

    def threshstate(self, reading):

        threshDecr = {
            0x00: "Uninitialized",
            0x01: "Normal",
            0x02: "Upper Non-Critical",
            0x04: "Upper Critical",
            0x08: "Lower Non-Critical",
            0x10: "Lower Critical",
            0x20: "Access Failed",
            0x40: "Upper Non-Recoverable",
            0x80: "Lower Non-Recoverable",
        }

        threshColor = {
            0x00: "bgcolor=white",
            0x01: "bgcolor=green",
            0x02: "bgcolor=yellow",
            0x04: "bgcolor=red",
            0x08: "bgcolor=yellow",
            0x10: "bgcolor=red",
            0x20: "bgcolor=red",
            0x40: "bgcolor=red",
            0x80: "bgcolor=red",
        }

        return [threshDecr[reading], threshColor[reading]]

    def sensorSpecific(self, type, reading):

        if type == "psu":

            PSUreadingDescr = {
                0: "Presence Detected",
                1: "Power Supply Failure Detected",
                2: "Predictive Failure Asserted",
                3: "Power Supply Input Lost (AC/DC)",
                4: "Power Supply Input Lost or Out of Range",
                5: "Power Supply Input Out of Range, but Present",
                6: "Configuration Error",
            }

            color = "bgcolor=green" if reading == 0 else "bgcolor=red"

            return PSUreadingDescr[reading], color

        if type == "driveslotbay":

            DRIVEreadingDescr = {
                0: "Drive Presence",
                1: "Drive Fault",
                2: "Predictive Failure",
                3: "Hot Spare",
                4: "Consistency Check / Parity Check in progress",
                5: "In Critical Array",
                6: "In Failed Array",
                7: "Rebuild/Remap in progress",
                8: "Rebuild/Remap Aborted",
            }

            color = "bgcolor=green" if reading == 0 else "bgcolor=red"

            return DRIVEreadingDescr[reading], color

        if type == "chassis":

            ChassisreadingDescr = {
                0: "General Chassis Intrusion",
                1: "Drive Bay Intrusion",
                2: "I/O Card Area Intrusion",
                3: "Processor Area Intrusion",
                4: "LAN Leash Lost (System unplugged from LAN)",
                5: "Unauthorized Dock",
                6: "Fan Area Intrusion",
            }

            return ChassisreadingDescr[reading], "bgcolor=red"

        if type == "memory":

            MEMORYreadingDescr = {
                0: "Correctable ECC",
                1: "Uncorrectable ECC",
                2: "Parity",
                3: "Memory Scrub Failure",
                4: "Memory Device Disabled",
                5: "Correctable ECC Logging Limit Reached",
                6: "Presence Detected",
                7: "Configuration Error",
                8: "Spare",
                9: "Memory Automatically Throttled",
                10: "Critical Overtemperature",
            }

            values = [3, 4, 5, 7, 9, 10, 8]

            color = "bgcolor=red" if any(reading == value for value in values) else "bgcolor=green"

            return MEMORYreadingDescr[reading], color

        return "Unknown", "bgcolor=white"

    def unitType(self, unitID):

        unitDef = {
            "0": "bool",
            "1": "degrees C",
            "2": "degrees F",
            "3": "degrees K",
            "4": "Volts",
            "5": "Amps",
            "6": "Watts",
            "7": "Joules",
            "18": "R.P.M",
            "19": "Hz",
        }

        try:
            return unitDef[unitID]

        except Exception:
            return None

    def webfetch(self):

        POST_LOGIN_URL = "%s://%s/rpc/WEBSES/create.asp" % (self.PROTO, self.IP)

        REQUEST_URL = "%s://%s/rpc/getallsensors.asp" % (self.PROTO, self.IP)

        LOGOUT_URL = "%s://%s/rpc/WEBSES/logout.asp" % (self.PROTO, self.IP)

        payload = {"WEBVAR_USERNAME": self.UNAME, "WEBVAR_PASSWORD": self.PASSWD}

        jsonObj = None

        with requests.session() as session:

            try:

                post = session.post(POST_LOGIN_URL, data=payload, timeout=6.0, verify=False)

                jsonObj = json.loads(self.fixJSON(post.text))

                cookieId = jsonObj["WEBVAR_JSONVAR_WEB_SESSION"]["WEBVAR_STRUCTNAME_WEB_SESSION"][
                    0
                ]["SESSION_COOKIE"]

                csrftoken = jsonObj["WEBVAR_JSONVAR_WEB_SESSION"]["WEBVAR_STRUCTNAME_WEB_SESSION"][
                    0
                ]["CSRFTOKEN"]

                headers = {
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                    "Host": "%s" % (self.IP),
                    "Referer": "%s://%s/page/sensor_reading.html" % (self.PROTO, self.IP),
                    "Cookie": "test=1; SessionCookie=%s; BMC_IP_ADDR=%s; Language=EN; Username=admin; PNO=4; Extendedpriv=259; gMultiLAN=true; settings={eth:[0,1],ethstr:['eth0','eth1'],lan:[1,8],enable:[1,1],ethstrings:['DM_LAN1','Shared LAN'],features:'NWLINK,SYSTEM_FIREWALL,EXTENDED_PRIV,CIRCULAR_SEL,SAVE_SELLOG,SET_SENSOR_THRESHOLDS,JAVASOL,NWBONDING,PAM_REORDERING,POWER_CONSUMPTION,SERVICES,SESSION_MANAGEMENT=SESSION_MANAGEMENT,SECTIONFLASH,VERSION_CMP_FLASH,NTP_SERVER_SUPPORT,SINGLE_PORT_APP,RUNTIME_SINGLEPORT_SUPPORT,SNMP,IMG_REDIRECTION,LMEDIA,TSIG,PRESERVECONF,IMG_REDIRECTION,RMEDIA,MDNS,TIMEZONE_SUPPORT,WEB_PREVIEW,CAPTURE_BSOD_RAW,CAPTURE_BSOD_RAW,AUTOVDORECORD,AUTOVDORECORD_REMOTE,KB_LANG_SELECT_SUPPORT,RUNTIME_HOST_LOCK,HOST_LOCK_AUTO,AUTO_RESIZE_KVM_CLIENT_WINDOW,MEDIA_REDIR_READ_WRITE_ONLY,MULTIPLE_USER_VMEDIA,DEDICATED_MEDIA_FOR_LMEDIA_RMEDIA,NCSI_SUPPORT,AD_SUPPORT,LDAP_SUPPORT,RADIUS_SUPPORT,'}"
                    % (cookieId, self.IP),
                    "CSRFTOKEN": csrftoken,
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
                }

                resp = session.get(REQUEST_URL, headers=headers, timeout=6.0, verify=False)

                headers["Referer"] = "%s://%s/index.html" % (self.PROTO, self.IP)

                session.get(LOGOUT_URL, headers=headers, timeout=6.0, verify=False)

                post.close()
                resp.close()
                session.close()

                jsonObj = json.loads((self.fixJSON(resp.text)))

            except Exception as e:

                if self.LOG:

                    with open("ipmi_poller_err", "a+") as fo:
                        fo.write(
                            str(datetime.datetime.now())
                            + " "
                            + self.HOSTNAME
                            + " webfetch --> "
                            + str(e)
                            + "\r\n"
                        )

                else:
                    print(
                        str(datetime.datetime.now())
                        + " "
                        + self.HOSTNAME
                        + " webfetch --> "
                        + str(e)
                        + "\r\n"
                    )

        return jsonObj

    def sensorProcess(self, jsonObj):

        self.sensorDB = {}

        self.sensorDB[self.IP] = {"hostname": self.HOSTNAME, "sensors": []}

        for sensor in jsonObj["WEBVAR_JSONVAR_HL_GETALLSENSORS"][
            "WEBVAR_STRUCTNAME_HL_GETALLSENSORS"
        ]:

            sID = sensor["SensorNumber"]
            sType = self.TypeResolve(sensor["SensorType"])
            sValue = sensor["SensorReading"]
            sValueDescr = None
            sName = sensor["SensorName"]
            sState = sensor["SensorState"]
            sDescreteState = sensor["DiscreteState"]
            sUnit = self.unitType(str(sensor["SensorUnit2"]))
            state = "Present"
            color = "bgcolor=white"

            if sensor["SensorAccessibleFlags"] != 213:

                if sType == "voltage":

                    sValue = float(sValue) / 1000.0

                else:

                    sValue = int(sValue / 1000)

                if sState:

                    for whichbit in range(0, 7):
                        if sState & (0x01 << whichbit):
                            sValueDescr, color = self.threshstate(0x01 << whichbit)

                    if sValue == 0 and sType == "temperature":
                        state = "Not Present"
                        sValueDescr = "N/A"
                        color = "bgcolor=white"

                else:

                    DiscreteSensorReading = sValue

                    if sDescreteState == 0x6F:

                        for whichbit in range(0, 7):

                            if DiscreteSensorReading & 0x01:
                                sValue = whichbit
                                sValueDescr, color = self.sensorSpecific(sType, whichbit)

                            DiscreteSensorReading = DiscreteSensorReading >> 1

                    if sValueDescr is None:

                        sValueDescr = "All deasserted"
                        sValue = 255
                        state = "Not Present"
                        color = "bgcolor=white"

                    if sValue == 0 and sState:

                        sValueDescr = "Not Available"

            else:

                if sValue == 0 and (sDescreteState == 0x6F or "AC Lost" in sName):
                    sValue = 0

                sValueDescr = "Not Available"
                state = "Not Present"

            self.sensorDB[self.IP]["sensors"].append(
                {
                    "id": sID,
                    "sensor": sName,
                    "type": sType,
                    "unit": sUnit,
                    "d_value": sValue,
                    "description": sValueDescr,
                    "color": color,
                    "state": state,
                    "hostname": self.HOSTNAME,
                }
            )

        # print(sName, sType, sState, sValue, sValueDescr, sUnit, state)

    def returnServer(self):
        return [server for server in self.sensorDB]

    def returnSensors(self, server):

        if self.state:
            return [sensors for sensors in self.sensorDB[server]["sensors"]]

        else:
            return [
                sensor
                for sensor in self.sensorDB[server]["sensors"]
                if sensor["state"] == "Present"
            ]

    def __init__(self, **kwargs):

        self.UNAME = "admin"
        self.PASSWD = "admin"
        self.HOSTNAME = "ASUS_ASMB8"
        self.state = True
        self.PROTO = "https"
        self.LOG = True
        self.verbose = None

        for key, value in kwargs.items():

            if ("user" in key) and (value):
                self.UNAME = value

            if ("passwd" in key) and (value):
                self.PASSWD = value

            if ("address" in key) and (value):
                self.IP = value

            if ("hostname" in key) and (value):
                self.HOSTNAME = value

            if ("state" in key) and (value):
                self.state = None

            if ("nosecure" in key) and (value):
                self.PROTO = "http"

            if ("nolog" in key) and (value):
                self.LOG = None

            if ("verbose" in key) and (value):
                self.verbose = True


def main():

    parser = argparse.ArgumentParser(description="IPMI Web Scrubber for ASM8 Servers")
    parser.add_argument("-H", "--host", metavar="", required=True, help="IP to query against")
    parser.add_argument("-U", "--user", metavar="", required=False, help="Username")
    parser.add_argument("-P", "--password", metavar="", required=False, help="Password")
    parser.add_argument("-N", "--hostname", metavar="", required=False, help="Custom Hostname")
    parser.add_argument(
        "-S", "--state", action="store_true", required=False, help="Omit non active sensors"
    )
    parser.add_argument(
        "-SSL", "--nosecure", action="store_true", required=False, help="Use http instead of https"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pretty", action="store_true", help="Print something pretty")
    group.add_argument("-d", "--dump", action="store_true", help="Dumps some xml and json")
    group.add_argument("-v", "--verbose", action="store_true", help="Pretty verbose")
    args = parser.parse_args()

    # ipmi = poller(address="192.168.10.31")

    ipmi = poller(
        address=args.host,
        hostname=args.hostname,
        nolog=True,
        verbose=args.verbose,
        state=args.state,
        user=args.user,
        passwd=args.password,
        nosecure=args.nosecure,
    )

    _dict = ipmi.webfetch()

    if isinstance(_dict, dict):

        if args.verbose:
            print(json.dumps(_dict, indent=3))

        ipmi.sensorProcess(_dict)

        documents = []

        for host in ipmi.returnServer():
            for sensor in ipmi.returnSensors(host):

                if args.pretty or args.verbose:
                    print(sensor)

                document = {"fields": sensor, "host": host}

                documents.append(document)

        if args.dump or args.verbose:
            print(json.dumps(documents, indent=4, sort_keys=False))


if __name__ == "__main__":
    main()
