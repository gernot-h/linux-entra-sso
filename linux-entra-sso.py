#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG

# pylint: disable=missing-docstring,invalid-name

# Renable invalid-name check, it should only cover the module name
# pylint: enable=invalid-name

import argparse
import sys
import json
import struct
import uuid
import logging
from pathlib import Path
from threading import Lock
from subprocess import Popen, PIPE, STDOUT

# version is replaced on installation
LINUX_ENTRA_SSO_VERSION = "0.0.0-dev"

# the ssoUrl is a mandatory parameter when requesting a PRT SSO
# Cookie, but the correct value is not checked as of 30.05.2024
# by the authorization backend. By that, a static (fallback)
# value can be used, if no real value is provided.
SSO_URL_DEFAULT = "https://login.microsoftonline.com/"
BROKER_START_TIMEOUT = 5
# dbus start service reply codes
START_REPLY_SUCCESS = 1
START_REPLY_ALREADY_RUNNING = 2
# prctl constants
PR_SET_PDEATHSIG = 1


class NativeMessaging:
    @staticmethod
    def get_message():
        """
        Read a message from stdin and decode it.
        """
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            sys.exit(0)
        message_length = struct.unpack("@I", raw_length)[0]
        message = sys.stdin.buffer.read(message_length).decode("utf-8")
        return json.loads(message)

    @staticmethod
    def encode_message(message_content):
        """
        Encode a message for transmission, given its content
        """
        encoded_content = json.dumps(message_content, separators=(",", ":")).encode(
            "utf-8"
        )
        encoded_length = struct.pack("@I", len(encoded_content))
        return {"length": encoded_length, "content": encoded_content}

    @staticmethod
    def send_message(encoded_message):
        """
        Send an encoded message to stdout
        """
        sys.stdout.buffer.write(encoded_message["length"])
        sys.stdout.buffer.write(encoded_message["content"])
        sys.stdout.buffer.flush()


class SsoMib:
    BROKER_NAME = 'C:\\Program Files\\Windows Security\\BrowserCore\\BrowserCore.exe'
    BROKER_PARAM = 'chrome-extension://ppnbnpeolgkicgegkbkbjmhlideopiji/'
    GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

    def __init__(self, daemon=False):
        self.broker = None
        self.session_id = uuid.uuid4()
        self._state_changed_cb = None
        if daemon:
            self._introspect_broker(fail_on_error=False)

    def _introspect_broker(self, fail_on_error=True):
        if self.broker:
            return
        self.broker = Popen([self.BROKER_NAME, self.BROKER_PARAM, '--parent-window=0'],
                            stdout=PIPE, stdin=PIPE, stderr=STDOUT)
#        if self._state_changed_cb:
#            self._state_changed_cb(True)

    def _communicate(self, msg):
        msg = json.dumps(msg)
        msg = msg.encode("utf-8")
        size = struct.pack("@L", len(msg))  # native byte-order, unsigned long (32 bits)
        stdout = self.broker.communicate(input=size + msg)[0]
        self.broker = None
        logging.debug("rcvd raw: " + str(stdout))
        resp = stdout.strip()[4:].decode()
        resp = json.loads(resp)
        return resp

    def on_broker_state_changed(self, callback):
        """
        Register a callback to be called when the broker state changes.
        The callback should accept a single boolean argument, indicating
        if the broker is online or not.
        """
        self._state_changed_cb = callback

    def get_accounts(self):
        return {"accounts": [{"name": "Windows User", "username": "windows_user"}]}

    def acquire_prt_sso_cookie(
        self, account, sso_url, scopes=GRAPH_SCOPES
    ):  # pylint: disable=dangerous-default-value
        logging.debug("acquire for "+sso_url)
        self._introspect_broker()
        request = {
            "method": "GetCookies",
            "sender": "https://login.microsoftonline.com/",
            "uri": sso_url,
        }
        resp = self._communicate(request)
        logging.debug("acquire cookie resp: " + str(resp))
        if len(resp["response"]) > 1:
            logging.warning("got multiple cookies: " + str(resp))
        resp = resp["response"][0]
        resp = {
            "cookieName": resp["name"],
            "cookieContent": resp["data"].split(";")[0]
        }
        logging.debug("send response: " + str(resp))
        return resp

    def acquire_token_silently(
        self, account, scopes=GRAPH_SCOPES
    ):  # pylint: disable=dangerous-default-value
        return {"error": "not implemented"}

    def get_broker_version(self):
        resp = {"linuxBrokerVersion": -1}
        resp["native"] = LINUX_ENTRA_SSO_VERSION
        return resp


def run_as_native_messaging():
    iomutex = Lock()
    log_file = Path.home() / "linux-entra-sso.log"
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s %(message)s')
    logging.debug("run_as_native_messaging")

    processing_error = {"error": "Failure during request processing"}

    def respond(command, message):
        logging.debug("send_message "+command)
        NativeMessaging.send_message(
            NativeMessaging.encode_message({"command": command, "message": message})
        )

    def notify_state_change(online):
        with iomutex:
            respond("brokerStateChanged", "online" if online else "offline")

    def handle_command(cmd, received_message):
        logging.debug("handle "+cmd)
        if cmd == "acquirePrtSsoCookie":
            account = received_message["account"]
            sso_url = received_message["ssoUrl"] or SSO_URL_DEFAULT
            token = ssomib.acquire_prt_sso_cookie(account, sso_url)
            respond(cmd, token)
        elif cmd == "acquireTokenSilently":
            account = received_message["account"]
            scopes = received_message.get("scopes") or ssomib.GRAPH_SCOPES
            token = ssomib.acquire_token_silently(account, scopes)
            respond(cmd, token)
        elif cmd == "getAccounts":
            respond(cmd, ssomib.get_accounts())
        elif cmd == "getVersion":
            respond(cmd, ssomib.get_broker_version())

    print("Running as native messaging instance.", file=sys.stderr)
    print("For interactive mode, start with --interactive", file=sys.stderr)

    # on chrome and chromium, the parent process does not reliably
    # terminate the process when the parent process is killed.
    # register_terminate_with_parent()

    ssomib = SsoMib(daemon=True)
    ssomib.on_broker_state_changed(notify_state_change)
    # inform other side about initial state
    notify_state_change(bool(ssomib.broker))
    while True:
        received_message = NativeMessaging.get_message()
        with iomutex:
            cmd = received_message["command"]
            logging.debug("received cmd "+cmd)
            try:
                handle_command(cmd, received_message)
            except Exception:  # pylint: disable=broad-except
                logging.exception("processing error")
                respond(cmd, processing_error)


def run_interactive():
    def _get_account(accounts, idx):
        try:
            return accounts["accounts"][idx]
        except IndexError:
            json.dump(
                {"error": f"invalid account index {idx}"},
                indent=2,
                fp=sys.stdout,
            )
            print()
            sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="run in interactive mode",
    )
    parser.add_argument(
        "-a",
        "--account",
        type=int,
        default=0,
        help="account index to use for operations",
    )
    parser.add_argument(
        "-s",
        "--ssoUrl",
        default=SSO_URL_DEFAULT,
        help="ssoUrl part of SSO PRT cookie request",
    )
    parser.add_argument(
        "command",
        choices=[
            "getAccounts",
            "getVersion",
            "acquirePrtSsoCookie",
            "acquireTokenSilently",
            "monitor",
        ],
    )
    args = parser.parse_args()

    ssomib = SsoMib(daemon=False)

    accounts = ssomib.get_accounts()
    if len(accounts["accounts"]) == 0:
        print("warning: no accounts registered.", file=sys.stderr)

    if args.command == "getAccounts":
        json.dump(accounts, indent=2, fp=sys.stdout)
    elif args.command == "getVersion":
        json.dump(ssomib.get_broker_version(), indent=2, fp=sys.stdout)
    elif args.command == "acquirePrtSsoCookie":
        account = _get_account(accounts, args.account)
        cookie = ssomib.acquire_prt_sso_cookie(account, args.ssoUrl)
        json.dump(cookie, indent=2, fp=sys.stdout)
    elif args.command == "acquireTokenSilently":
        account = _get_account(accounts, args.account)
        token = ssomib.acquire_token_silently(account)
        json.dump(token, indent=2, fp=sys.stdout)
    # add newline
    print()


if __name__ == "__main__":
    if "--interactive" in sys.argv or "-i" in sys.argv:
        run_interactive()
    else:
        run_as_native_messaging()
