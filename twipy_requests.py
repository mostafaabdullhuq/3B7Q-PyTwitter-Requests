__author = "Mostafa Abdullhuq (3B7Q)"

from functools import wraps
import requests
from bs4 import BeautifulSoup
from re import findall
from json import dumps, loads
from re import findall
import requests
import time
from threading import Thread,Lock
from time import sleep
from os import system, mkdir, path
import struct
from random import choice
import sys




class Twitter:

    # constructor function of the class
    def __init__(self):
        self.__user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.15 Safari/537.36 Edg/101.0.1210.10"
        self.__bearer_token = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        self.session = requests.Session()
        self.__guest_token = None
        self.__is_logged_in = False
        self.__is_banned = False
        self.__is_suspended = False


    def login_required(self, func):
        """decorator to ensure that is user is logged in before performing specific action

        Args:
            func (func): A function that performs an action that you want to ensure that user is logged in before doing it.
        """
        def nested_function(*args, **kwargs):
            if self.__is_logged_in:
                func(*args, **kwargs)
            else:
                yield "Your must be logged in to perform this action."
        return nested_function

    @property
    def user_agent(self):
        """
        Returns:
            str: the current user agent of the session.
        """
        return self.__user_agent

    @property
    def bearer_token(self):
        """

        Returns:
            str: the current bearer token of the session.
        """
        return self.__bearer_token

    def change_bearer_token(self, new_bearer: str):
        """changes the current bearer token of the session

        Args:
            new_bearer (str): the new value of the bearer token you want to use in the session
        """
        self.__bearer_token = new_bearer

    def change_user_agent(self, new_agent: str):
        """changes the current user agent of the session

        Args:
            new_agent (str): the new value of the user agent you want to use in the session
        """
        self.__user_agent = new_agent
    
    @login_required
    @property
    def is_account_banned(self):
        """A property that determines the state of the logged in account whether it's banned or not. (User must be logged in to perform this action)

        Returns:
            bool: True if the user is banned, False if not.
        """
        return self.__is_banned
    
    @login_required
    @property
    def is_account_suspended(self):
        """A property that determines the state of the logged in account whether it's suspended or not. (User must be logged in to perform this action)

        Returns:
            bool: True if the user is suspended, False if not.
        """
        return self.__is_suspended

    @property
    def is_logged_in(self):
        """A property that determines if there's a user already logged in or not.

        Returns:
            bool: True if user is already logged in, False if not.
        """
        return self.__is_logged_in
    
    @property
    def guest_token(self):
        """
        Returns:
            str: The current guest token.
        """
        return self.__guest_token
    
    def change_guest_token(self, new_guest_token: str):
        """Manually changes the current guest token with a new one.

        Args:
            new_guest_token (str): the new value of the guest token.
        """
        self.__guest_token = new_guest_token

    def generate_guest_token(self):
        """generates new guest_token and automatically assign it to the guest_token variable

        Returns:
            list: first element is the state of the request, second element is the details about the request response.
        """
        get_guest_token_headers = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'sec-ch-ua': '"Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'DNT': '1', 'Upgrade-Insecure-Requests': '1', 'User-Agent': self.user_agent, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1', 'Sec-Fetch-Dest': 'document', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9'}
        get_guest_token = requests.get(f"https://twitter.com/",headers=get_guest_token_headers)
        if get_guest_token.status_code == 200 and 'decodeURIComponent("gt' in get_guest_token.text:
            try:
                guest_token = findall('decodeURIComponent\("gt=(\d*);',get_guest_token.text)[0]
                self.change_guest_token(guest_token)
                return [True, guest_token]
            except:
                return [False, get_guest_token]
        else:
            return [False, get_guest_token]

    def login(self, username: str, password: str, challenge_method: str, proxy:str = False):
        """login to account to start performing actions
        Args:
            username (str): the username of the account.
            password (str): the password of the account.
            challenge_method (str): email or phone number used for verification method.
            proxy (str): proxy used to login (Optional).
        Returns:
            list: first element is the state of the request, second element is the details about the request response.
        """
        if proxy:
            self.session.proxies.update({
                "https":f"http://{proxy}",
                "http":f"http://{proxy}"
            })
        get_login_headers = {
            "Host": "twitter.com",
            "Connection": "keep-alive",
            "sec-ch-ua":
            '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent":
            self.user_agent,
            "Accept":
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-GPC": "1",
        }
        get_login = self.session.get("https://twitter.com/login",headers=get_login_headers)
        if (get_login.status_code == 200 and 'meta property="og:site_name" content="Twitter' in get_login.text):
            get_sw_js_headers = {
                "Host": "twitter.com",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=0",
                "DNT": "1",
                "Accept": "*/*",
                "Service-Worker": "script",
                "User-Agent":
                self.user_agent,
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "same-origin",
                "Sec-Fetch-Dest": "serviceworker",
                "Referer": "https://twitter.com/login",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-GPC": "1",
            }
            get_sw_js = self.session.get("https://twitter.com/sw.js", headers=get_sw_js_headers)
            if get_sw_js.status_code == 200 and "self.ASSETS=" in get_sw_js.text:
                getHomeHeaders = {
                    "Host": "twitter.com",
                    "Connection": "keep-alive",
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "User-Agent":
                    self.user_agent,
                    "DNT": "1",
                    "Accept": "*/*",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "same-origin",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": "https://twitter.com/sw.js",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Sec-GPC": "1",
                }
                get_home = self.session.get("https://twitter.com/home?precache=1", headers=getHomeHeaders)
                if get_home.status_code == 200 and "https://twitter.com/home" in get_home.url:
                    guest_option_headers = {
                        "Host": "api.twitter.com",
                        "Connection": "keep-alive",
                        "Accept": "*/*",
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers":
                        "authorization,x-csrf-token,x-twitter-active-user,x-twitter-client-language",
                        "Origin": "https://twitter.com",
                        "User-Agent":
                        self.user_agent,
                        "Sec-Fetch-Mode": "cors",
                        "Sec-Fetch-Site": "same-site",
                        "Sec-Fetch-Dest": "empty",
                        "Referer": "https://twitter.com/",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "en-US,en;q=0.9",
                        "DNT": "1",
                        "Sec-GPC": "1",
                    }
                    guest_options = self.session.options("https://api.twitter.com/1.1/guest/activate.json", headers=guest_option_headers)
                    if guest_options.status_code == 200 and guest_options.text == "":
                        guest_post_headers = {
                            "Host": "api.twitter.com",
                            "Connection": "keep-alive",
                            "Content-Length": "0",
                            "sec-ch-ua":
                            '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                            "DNT": "1",
                            "x-twitter-client-language": "en",
                            "sec-ch-ua-mobile": "?0",
                            "authorization":
                            f"Bearer {self.bearer_token}",
                            "content-type": "application/x-www-form-urlencoded",
                            "User-Agent":
                            self.user_agent,
                            "x-twitter-active-user": "yes",
                            "sec-ch-ua-platform": '"Windows"',
                            "Accept": "*/*",
                            "Origin": "https://twitter.com",
                            "Sec-Fetch-Site": "same-site",
                            "Sec-Fetch-Mode": "cors",
                            "Sec-Fetch-Dest": "empty",
                            "Referer": "https://twitter.com/",
                            "Accept-Encoding": "gzip, deflate, br",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Sec-GPC": "1",
                        }
                        guest_post = self.session.post("https://api.twitter.com/1.1/guest/activate.json", headers=guest_post_headers)
                        if (guest_post.status_code == 200 and "guest_token" in guest_post.text):
                            self.change_guest_token(guest_post.json()["guest_token"])
                            client_event_options_headers = {
                                "Host": "api.twitter.com",
                                "Connection": "keep-alive",
                                "Accept": "*/*",
                                "Access-Control-Request-Method": "POST",
                                "Access-Control-Request-Headers":
                                "authorization,x-csrf-token,x-guest-token,x-twitter-active-user,x-twitter-client-language",
                                "Origin": "https://twitter.com",
                                "User-Agent":
                                self.user_agent,
                                "Sec-Fetch-Mode": "cors",
                                "Sec-Fetch-Site": "same-site",
                                "Sec-Fetch-Dest": "empty",
                                "Referer": "https://twitter.com/",
                                "Accept-Encoding": "gzip, deflate, br",
                                "Accept-Language": "en-US,en;q=0.9",
                                "DNT": "1",
                                "Sec-GPC": "1",
                            }
                            client_event_options = self.session.options("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_options_headers)
                            if (client_event_options.status_code == 200 and client_event_options.text == ""):
                                graph_ql_headers = {
                                    "Host": "twitter.com",
                                    "Connection": "keep-alive",
                                    "sec-ch-ua":
                                    '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                    "DNT": "1",
                                    "x-twitter-client-language": "en",
                                    "sec-ch-ua-mobile": "?0",
                                    "authorization":
                                    f"Bearer {self.bearer_token}",
                                    "content-type": "application/json",
                                    "User-Agent":
                                    self.user_agent,
                                    "x-guest-token": self.guest_token,
                                    "x-twitter-active-user": "yes",
                                    "sec-ch-ua-platform": '"Windows"',
                                    "Accept": "*/*",
                                    "Sec-Fetch-Site": "same-origin",
                                    "Sec-Fetch-Mode": "cors",
                                    "Sec-Fetch-Dest": "empty",
                                    "Referer": "https://twitter.com/i/flow/login",
                                    "Accept-Encoding": "gzip, deflate, br",
                                    "Accept-Language": "en-US,en;q=0.9",
                                    "Sec-GPC": "1",
                                }
                                graph_ql = self.session.get("https://twitter.com/i/api/graphql/CMIp0zch4ndojEgt5IObcw/Viewer?variables=%7B%22withCommunitiesMemberships%22%3Atrue%2C%22withCommunitiesCreation%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Atrue%7D", headers=graph_ql_headers)
                                if (graph_ql.status_code == 200 and 'message"' in graph_ql.text):
                                    client_event_options_2_headers = {
                                        "Host": "api.twitter.com",
                                        "Connection": "keep-alive",
                                        "Accept": "*/*",
                                        "Access-Control-Request-Method": "POST",
                                        "Access-Control-Request-Headers":
                                        "authorization,x-csrf-token,x-guest-token,x-twitter-active-user,x-twitter-client-language",
                                        "Origin": "https://twitter.com",
                                        "User-Agent":
                                        self.user_agent,
                                        "Sec-Fetch-Mode": "cors",
                                        "Sec-Fetch-Site": "same-site",
                                        "Sec-Fetch-Dest": "empty",
                                        "Referer": "https://twitter.com/",
                                        "Accept-Encoding": "gzip, deflate, br",
                                        "Accept-Language": "en-US,en;q=0.9",
                                        "DNT": "1",
                                        "Sec-GPC": "1",
                                    }
                                    client_event_options_2 = self.session.options("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_options_2_headers)
                                    if (client_event_options_2.status_code == 200 and client_event_options_2.text == ""):
                                        client_event_post_headers = {
                                            "Host": "api.twitter.com",
                                            "Connection": "keep-alive",
                                            "Content-Length": "152",
                                            "sec-ch-ua":
                                            '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                            "DNT": "1",
                                            "x-twitter-client-language": "en",
                                            "sec-ch-ua-mobile": "?0",
                                            "authorization":
                                            f"Bearer {self.bearer_token}",
                                            "content-type":
                                            "application/x-www-form-urlencoded",
                                            "User-Agent":
                                            self.user_agent,
                                            "x-guest-token": self.guest_token,
                                            "x-twitter-active-user": "no",
                                            "sec-ch-ua-platform": '"Windows"',
                                            "Accept": "*/*",
                                            "Origin": "https://twitter.com",
                                            "Sec-Fetch-Site": "same-site",
                                            "Sec-Fetch-Mode": "cors",
                                            "Sec-Fetch-Dest": "empty",
                                            "Referer": "https://twitter.com/",
                                            "Accept-Encoding": "gzip, deflate, br",
                                            "Accept-Language": "en-US,en;q=0.9",
                                            "Sec-GPC": "1",
                                        }

                                        client_event_post_data = {
                                            "category":
                                            "perftown",
                                            "log":
                                            '[{"description":"rweb:cookiesMetadata:load","product":"rweb","event_value":12616155236}]',
                                        }
                                        client_event_post = self.session.post("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_post_headers, data=client_event_post_data)
                                        if client_event_post.status_code == 200 and client_event_post.text == "":
                                            client_event_options_3_headers = {
                                                "Host": "api.twitter.com",
                                                "Connection": "keep-alive",
                                                "Accept": "*/*",
                                                "Access-Control-Request-Method":
                                                "POST",
                                                "Access-Control-Request-Headers":
                                                "authorization,x-csrf-token,x-guest-token,x-twitter-active-user,x-twitter-client-language",
                                                "Origin": "https://twitter.com",
                                                "User-Agent":
                                                self.user_agent,
                                                "Sec-Fetch-Mode": "cors",
                                                "Sec-Fetch-Site": "same-site",
                                                "Sec-Fetch-Dest": "empty",
                                                "Referer": "https://twitter.com/",
                                                "Accept-Encoding":
                                                "gzip, deflate, br",
                                                "Accept-Language":
                                                "en-US,en;q=0.9",
                                                "DNT": "1",
                                                "Sec-GPC": "1",
                                            }
                                            client_event_options_3 = self.session.options("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_options_3_headers)
                                            if (client_event_options_3.status_code == 200 and client_event_options_3.text == ""):
                                                attribute_post_headers = {
                                                    "Host": "twitter.com",
                                                    "Connection": "keep-alive",
                                                    "Content-Length": "16",
                                                    "sec-ch-ua":
                                                    '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                    "DNT": "1",
                                                    "x-twitter-client-language":
                                                    "en",
                                                    "sec-ch-ua-mobile": "?0",
                                                    "authorization":
                                                    f"Bearer {self.bearer_token}",
                                                    "content-type":
                                                    "application/json",
                                                    "User-Agent":
                                                    self.user_agent,
                                                    "x-guest-token": self.guest_token,
                                                    "x-twitter-active-user": "no",
                                                    "sec-ch-ua-platform":
                                                    '"Windows"',
                                                    "Accept": "*/*",
                                                    "Origin":
                                                    "https://twitter.com",
                                                    "Sec-Fetch-Site":
                                                    "same-origin",
                                                    "Sec-Fetch-Mode": "cors",
                                                    "Sec-Fetch-Dest": "empty",
                                                    "Referer":
                                                    "https://twitter.com/i/flow/login",
                                                    "Accept-Encoding":
                                                    "gzip, deflate, br",
                                                    "Accept-Language":
                                                    "en-US,en;q=0.9",
                                                    "Sec-GPC": "1",
                                                }

                                                attribute_post_data = loads(dumps('{"event": "open"}'))
                                                attribute_post = self.session.post("https://twitter.com/i/api/1.1/attribution/event.json", headers=attribute_post_headers, data=attribute_post_data)
                                                if ("session_token" in attribute_post.text and attribute_post.status_code == 200):
                                                    branch_init_post_headers = {
                                                        "Host": "twitter.com",
                                                        "Connection": "keep-alive",
                                                        "Content-Length": "2",
                                                        "sec-ch-ua":
                                                        '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                        "DNT": "1",
                                                        "x-twitter-client-language":
                                                        "en",
                                                        "sec-ch-ua-mobile": "?0",
                                                        "authorization":
                                                        f"Bearer {self.bearer_token}",
                                                        "content-type":
                                                        "application/json",
                                                        "User-Agent":
                                                        self.user_agent,
                                                        "x-guest-token":
                                                        self.guest_token,
                                                        "x-twitter-active-user":
                                                        "no",
                                                        "sec-ch-ua-platform":
                                                        '"Windows"',
                                                        "Accept": "*/*",
                                                        "Origin":
                                                        "https://twitter.com",
                                                        "Sec-Fetch-Site":
                                                        "same-origin",
                                                        "Sec-Fetch-Mode": "cors",
                                                        "Sec-Fetch-Dest": "empty",
                                                        "Referer":
                                                        "https://twitter.com/i/flow/login",
                                                        "Accept-Encoding":
                                                        "gzip, deflate, br",
                                                        "Accept-Language":
                                                        "en-US,en;q=0.9",
                                                        "Sec-GPC": "1",
                                                    }
                                                    branch_init_post_data = loads(dumps("{}"))
                                                    branch_init_post = self.session.post( "https://twitter.com/i/api/1.1/branch/init.json", headers=branch_init_post_headers, data=branch_init_post_data)
                                                    if (branch_init_post.status_code == 200 and "is_tracking_enabled" in branch_init_post.text):
                                                        onboarding_login_headers = {
                                                            "Host":
                                                            "twitter.com",
                                                            "Connection":
                                                            "keep-alive",
                                                            "Content-Length":
                                                            "233",
                                                            "sec-ch-ua":
                                                            '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                            "DNT":
                                                            "1",
                                                            "x-twitter-client-language":
                                                            "en",
                                                            "sec-ch-ua-mobile":
                                                            "?0",
                                                            "authorization":
                                                            f"Bearer {self.bearer_token}",
                                                            "content-type":
                                                            "application/json",
                                                            "User-Agent":
                                                            self.user_agent,
                                                            "x-guest-token":
                                                           self.guest_token,
                                                            "x-twitter-active-user":
                                                            "no",
                                                            "sec-ch-ua-platform":
                                                            '"Windows"',
                                                            "Accept":
                                                            "*/*",
                                                            "Origin":
                                                            "https://twitter.com",
                                                            "Sec-Fetch-Site":
                                                            "same-origin",
                                                            "Sec-Fetch-Mode":
                                                            "cors",
                                                            "Sec-Fetch-Dest":
                                                            "empty",
                                                            "Referer":
                                                            "https://twitter.com/i/flow/login",
                                                            "Accept-Encoding":
                                                            "gzip, deflate, br",
                                                            "Accept-Language":
                                                            "en-US,en;q=0.9",
                                                            "Sec-GPC":
                                                            "1",
                                                        }
                                                        onboarding_login_data = loads(dumps(
                                                                """{"input_flow_data": {"flow_context": {"debug_overrides": {},"start_location": {"location": "manual_link"}}},"subtask_versions": {"contacts_live_sync_permission_prompt": 0,"email_verification": 1,"topics_selector": 1,"wait_spinner": 1,"cta": 4}}"""
                                                            ))
                                                        onboarding_login = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json?flow_name=login", headers=onboarding_login_headers, data=onboarding_login_data)
                                                        if (onboarding_login.status_code == 200 and "flow_token" in onboarding_login.text):
                                                            flow_token = onboarding_login.json()["flow_token"]
                                                            get_ui_metrics_headers = {
                                                                "Host":
                                                                "twitter.com",
                                                                "Connection":
                                                                "keep-alive",
                                                                "sec-ch-ua":
                                                                '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                "DNT": "1",
                                                                "sec-ch-ua-mobile":
                                                                "?0",
                                                                "User-Agent":
                                                                self.user_agent,
                                                                "sec-ch-ua-platform":
                                                                '"Windows"',
                                                                "Accept": "*/*",
                                                                "Sec-Fetch-Site":
                                                                "same-origin",
                                                                "Sec-Fetch-Mode":
                                                                "no-cors",
                                                                "Sec-Fetch-Dest":
                                                                "script",
                                                                "Referer":
                                                                "https://twitter.com/i/flow/login",
                                                                "Accept-Encoding":
                                                                "gzip, deflate, br",
                                                                "Accept-Language":
                                                                "en-US,en;q=0.9",
                                                                "Sec-GPC": "1",
                                                            }
                                                            get_ui_metrics = self.session.get("https://twitter.com/i/js_inst?c_name=ui_metrics",headers=get_ui_metrics_headers,)
                                                            if (get_ui_metrics.status_code == 200 and "document.getElementsByName('ui_metrics" in get_ui_metrics.text):
                                                                responseData = findall(r"({'rf':{.*});};",get_ui_metrics.text)[0]
                                                                onboarding_task_headers = {
                                                                    "Host":
                                                                    "twitter.com",
                                                                    "Connection":
                                                                    "keep-alive",
                                                                    "Content-Length":
                                                                    "861",
                                                                    "sec-ch-ua":
                                                                    '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                    "DNT":
                                                                    "1",
                                                                    "x-twitter-client-language":
                                                                    "en",
                                                                    "sec-ch-ua-mobile":
                                                                    "?0",
                                                                    "authorization":
                                                                    f"Bearer {self.bearer_token}",
                                                                    "content-type":
                                                                    "application/json",
                                                                    "User-Agent":
                                                                    self.user_agent,
                                                                    "x-guest-token": self.guest_token,
                                                                    "x-twitter-active-user":
                                                                    "no",
                                                                    "sec-ch-ua-platform":
                                                                    '"Windows"',
                                                                    "Accept":
                                                                    "*/*",
                                                                    "Origin":
                                                                    "https://twitter.com",
                                                                    "Sec-Fetch-Site":
                                                                    "same-origin",
                                                                    "Sec-Fetch-Mode":
                                                                    "cors",
                                                                    "Sec-Fetch-Dest":
                                                                    "empty",
                                                                    "Referer":
                                                                    "https://twitter.com/i/flow/login",
                                                                    "Accept-Encoding":
                                                                    "gzip, deflate, br",
                                                                    "Accept-Language":
                                                                    "en-US,en;q=0.9",
                                                                    "Sec-GPC":
                                                                    "1",
                                                                }
                                                                onboarding_task_data = loads(dumps(
                                                                        f"""{{"flow_token": "{flow_token}","subtask_inputs": [{{"subtask_id": "LoginJsInstrumentationSubtask","js_instrumentation": {{"response": "{responseData}","link": "next_link"}}}}]}}"""
                                                                    ))
                                                                onboarding_task = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json", headers=onboarding_task_headers, data=onboarding_task_data)
                                                                if (onboarding_task.status_code== 200 and"flow_token" in onboarding_task.text and 'status":"success' in onboarding_task.text):
                                                                    flow_token2 = onboarding_task.json()["flow_token"]
                                                                    client_event_post_2_headers = {
                                                                        "Host":
                                                                        "api.twitter.com",
                                                                        "Connection":
                                                                        "keep-alive",
                                                                        "Content-Length":
                                                                        "2139",
                                                                        "sec-ch-ua":
                                                                        '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                        "DNT":
                                                                        "1",
                                                                        "x-twitter-client-language":
                                                                        "en",
                                                                        "sec-ch-ua-mobile":
                                                                        "?0",
                                                                        "authorization":
                                                                        f"Bearer {self.bearer_token}",
                                                                        "content-type":
                                                                        "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                        self.user_agent,
                                                                        "x-guest-token": self.guest_token,
                                                                        "x-twitter-active-user":
                                                                        "yes",
                                                                        "sec-ch-ua-platform":
                                                                        '"Windows"',
                                                                        "Accept":
                                                                        "*/*",
                                                                        "Origin":
                                                                        "https://twitter.com",
                                                                        "Sec-Fetch-Site":
                                                                        "same-site",
                                                                        "Sec-Fetch-Mode":
                                                                        "cors",
                                                                        "Sec-Fetch-Dest":
                                                                        "empty",
                                                                        "Referer":
                                                                        "https://twitter.com/",
                                                                        "Accept-Encoding":
                                                                        "gzip, deflate, br",
                                                                        "Accept-Language":
                                                                        "en-US,en;q=0.9",
                                                                        "Sec-GPC":
                                                                        "1",
                                                                    }
                                                                    client_event_post_2_data = {
                                                                        "debug":
                                                                        "true",
                                                                        "log":
                                                                        f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"event_namespace":{{"page":"onboarding","action":"show","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":1,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token}","name":"LoginJsInstrumentationSubtask"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":2,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token}","name":"LoginJsInstrumentationSubtask","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":3,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token2}","name":"LoginEnterUserIdentifierSSOSubtask"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":4,"client_app_id":"3033300"}}]'''
                                                                    }
                                                                    client_event_post_2 = self.session.post("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_post_2_headers, data=client_event_post_2_data)
                                                                    if (client_event_post_2.status_code == 200 and client_event_post_2.text == ""):
                                                                        client_event_post_3_headers = {
                                                                            "Host":
                                                                            "api.twitter.com",
                                                                            "Connection":
                                                                            "keep-alive",
                                                                            "Content-Length":
                                                                            "2139",
                                                                            "sec-ch-ua":
                                                                            '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                            "DNT":
                                                                            "1",
                                                                            "x-twitter-client-language":
                                                                            "en",
                                                                            "sec-ch-ua-mobile":
                                                                            "?0",
                                                                            "authorization":
                                                                            f"Bearer {self.bearer_token}",
                                                                            "content-type":
                                                                            "application/x-www-form-urlencoded",
                                                                            "User-Agent":
                                                                            self.user_agent,
                                                                            "x-guest-token":
                                                                           self.guest_token,
                                                                            "x-twitter-active-user":
                                                                            "yes",
                                                                            "sec-ch-ua-platform":
                                                                            '"Windows"',
                                                                            "Accept":
                                                                            "*/*",
                                                                            "Origin":
                                                                            "https://twitter.com",
                                                                            "Sec-Fetch-Site":
                                                                            "same-site",
                                                                            "Sec-Fetch-Mode":
                                                                            "cors",
                                                                            "Sec-Fetch-Dest":
                                                                            "empty",
                                                                            "Referer":
                                                                            "https://twitter.com/",
                                                                            "Accept-Encoding":
                                                                            "gzip, deflate, br",
                                                                            "Accept-Language":
                                                                            "en-US,en;q=0.9",
                                                                            "Sec-GPC":
                                                                            "1",
                                                                        }
                                                                        client_event_post_3_data = {
                                                                            "debug":"true",
                                                                            "log":f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token2}","name":"LoginEnterUserIdentifierSSOSubtask","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":5,"client_app_id":"3033300"}}]''',
                                                                        }
                                                                        client_event_post_3 = self.session.post("https://api.twitter.com/1.1/jot/client_event.json", headers=client_event_post_3_headers, data=client_event_post_3_data)
                                                                        if (client_event_post_3.status_code == 200 and client_event_post_3.text == ""):
                                                                            onboarding_user_login_headers = {
                                                                                "Host":
                                                                                "twitter.com",
                                                                                "Connection":
                                                                                "keep-alive",
                                                                                "Content-Length":
                                                                                "290",
                                                                                "sec-ch-ua":
                                                                                '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                                "DNT":
                                                                                "1",
                                                                                "x-twitter-client-language":
                                                                                "en",
                                                                                "sec-ch-ua-mobile":
                                                                                "?0",
                                                                                "authorization":
                                                                                f"Bearer {self.bearer_token}",
                                                                                "content-type":
                                                                                "application/json",
                                                                                "User-Agent":
                                                                                self.user_agent,
                                                                                "x-guest-token":
                                                                               self.guest_token,
                                                                                "x-twitter-active-user":
                                                                                "yes",
                                                                                "sec-ch-ua-platform":
                                                                                '"Windows"',
                                                                                "Accept":
                                                                                "*/*",
                                                                                "Origin":
                                                                                "https://twitter.com",
                                                                                "Sec-Fetch-Site":
                                                                                "same-origin",
                                                                                "Sec-Fetch-Mode":
                                                                                "cors",
                                                                                "Sec-Fetch-Dest":
                                                                                "empty",
                                                                                "Referer":
                                                                                "https://twitter.com/i/flow/login",
                                                                                "Accept-Encoding":
                                                                                "gzip, deflate, br",
                                                                                "Accept-Language":
                                                                                "en-US,en;q=0.9",
                                                                                "Sec-GPC":
                                                                                "1",
                                                                            }

                                                                            onboarding_user_login_data = loads(dumps(
                                                                                    f"""{{"flow_token": "{flow_token2}","subtask_inputs": [{{"subtask_id": "LoginEnterUserIdentifierSSO","settings_list": {{"setting_responses": [{{"key": "user_identifier","response_data": {{"text_data": {{"result": "{username}"}}}}}}],"link": "next_link"}}}}]}}"""
                                                                                ))
                                                                            onboarding_user_login = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json", headers=onboarding_user_login_headers,data=onboarding_user_login_data)
                                                                            if (onboarding_user_login.status_code == 200 and 'status":"success' in onboarding_user_login.text and "flow_token" in onboarding_user_login.text):
                                                                                flow_token3 = onboarding_user_login.json()["flow_token"]
                                                                                onboarding_password_login_headers = {
                                                                                    "Host":
                                                                                    "twitter.com",
                                                                                    "Connection":
                                                                                    "keep-alive",
                                                                                    "Content-Length":
                                                                                    "196",
                                                                                    "sec-ch-ua":
                                                                                    '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                                    "DNT":
                                                                                    "1",
                                                                                    "x-twitter-client-language":
                                                                                    "en",
                                                                                    "sec-ch-ua-mobile":
                                                                                    "?0",
                                                                                    "authorization":
                                                                                    f"Bearer {self.bearer_token}",
                                                                                    "content-type":
                                                                                    "application/json",
                                                                                    "User-Agent":
                                                                                    self.user_agent,
                                                                                    "x-guest-token": self.guest_token,
                                                                                    "x-twitter-active-user":
                                                                                    "yes",
                                                                                    "sec-ch-ua-platform":
                                                                                    '"Windows"',
                                                                                    "Accept":
                                                                                    "*/*",
                                                                                    "Origin":
                                                                                    "https://twitter.com",
                                                                                    "Sec-Fetch-Site":
                                                                                    "same-origin",
                                                                                    "Sec-Fetch-Mode":
                                                                                    "cors",
                                                                                    "Sec-Fetch-Dest":
                                                                                    "empty",
                                                                                    "Referer":
                                                                                    "https://twitter.com/i/flow/login",
                                                                                    "Accept-Encoding":
                                                                                    "gzip, deflate, br",
                                                                                    "Accept-Language":
                                                                                    "en-US,en;q=0.9",
                                                                                    "Sec-GPC":
                                                                                    "1",
                                                                                }

                                                                                onboarding_password_login_data = loads(dumps(
                                                                                        f"""{{"flow_token": "{flow_token3}","subtask_inputs": [{{"subtask_id": "LoginEnterPassword","enter_password": {{"password": "{password}","link": "next_link"}}}}]}}"""))
                                                                                onboarding_password_login = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json", headers=onboarding_password_login_headers, data=onboarding_password_login_data)
                                                                                if (onboarding_password_login.status_code == 200 and "flow_token" in onboarding_password_login.text and 'status":"success' in onboarding_password_login.
                                                                                        text):
                                                                                    flow_token4 = onboarding_password_login.json()["flow_token"]
                                                                                    onboarding_check_duplication_headers = {
                                                                                        "Host":
                                                                                        "twitter.com",
                                                                                        "Connection":
                                                                                        "keep-alive",
                                                                                        "Content-Length":
                                                                                        "206",
                                                                                        "sec-ch-ua":
                                                                                        '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
                                                                                        "DNT":
                                                                                        "1",
                                                                                        "x-twitter-client-language":
                                                                                        "en",
                                                                                        "sec-ch-ua-mobile":
                                                                                        "?0",
                                                                                        "authorization":
                                                                                        f"Bearer {self.bearer_token}",
                                                                                        "content-type":
                                                                                        "application/json",
                                                                                        "User-Agent":
                                                                                        self.user_agent,
                                                                                        "x-guest-token":
                                                                                       self.guest_token,
                                                                                        "x-twitter-active-user":
                                                                                        "yes",
                                                                                        "sec-ch-ua-platform":
                                                                                        '"Windows"',
                                                                                        "Accept":
                                                                                        "*/*",
                                                                                        "Origin":
                                                                                        "https://twitter.com",
                                                                                        "Sec-Fetch-Site":
                                                                                        "same-origin",
                                                                                        "Sec-Fetch-Mode":
                                                                                        "cors",
                                                                                        "Sec-Fetch-Dest":
                                                                                        "empty",
                                                                                        "Referer":
                                                                                        "https://twitter.com/i/flow/login",
                                                                                        "Accept-Encoding":
                                                                                        "gzip, deflate, br",
                                                                                        "Accept-Language":
                                                                                        "en-US,en;q=0.9",
                                                                                        "Sec-GPC":
                                                                                        "1",
                                                                                    }
                                                                                    onboarding_check_duplication_data = loads(dumps(
                                                                                            f"""{{"flow_token":"{flow_token4}","subtask_inputs":[{{"subtask_id":"AccountDuplicationCheck","check_logged_in_account":{{"link":"AccountDuplicationCheck_false"}}}}]}}"""))
                                                                                    onboarding_check_duplication = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json", headers=onboarding_check_duplication_headers, data=onboarding_check_duplication_data)
                                                                                    #! last login step
                                                                                    if (onboarding_check_duplication.status_code == 200 and "flow_token" in onboarding_check_duplication.text and 'status":"success' in onboarding_check_duplication.text):
                                                                                        flow_token5 = onboarding_check_duplication.json()["flow_token"]
                                                                                        isLoggedIn = False
                                                                                        if ('subtask_id":"LoginAcid' in onboarding_check_duplication.text and 'by entering the email address associated with your Twitter account'  in onboarding_check_duplication.text):
                                                                                            client_event_post_4_headers = {'host': 'api.twitter.com', 'content-length': '2913', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'content-type': 'application/x-www-form-urlencoded', 'accept': '*/*', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
                                                                                            client_event_post_4_data = {
                                                                                                'debug':'true',
                                                                                                'log':f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token3}","name":"LoginEnterPassword"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":8,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token3}","name":"LoginEnterPassword","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":9,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token4}","name":"AccountDuplicationCheck"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":10,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token4}","name":"AccountDuplicationCheck","description":"AccountDuplicationCheck_false"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":11,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token5}","name":"LoginAcid"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":12,"client_app_id":"3033300"}}]'''
                                                                                                                        }
                                                                                            client_event_post_4 = self.session.post('https://api.twitter.com/1.1/jot/client_event.json', headers=client_event_post_4_headers, data=client_event_post_4_data)
                                                                                            if client_event_post_4.status_code == 200 and client_event_post_4.text == '':
                                                                                                client_event_post_5_headers = {'host': 'api.twitter.com', 'content-length': '2913', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'content-type': 'application/x-www-form-urlencoded', 'accept': '*/*', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
                                                                                                client_event_post_5_data = {
                                                                                                    'debug':'true',
                                                                                                    'log':f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.getTimestamp()},"items":[{{"token":"{flow_token5}","name":"LoginAcid","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.getTimestamp()},"client_event_sequence_number":13,"client_app_id":"3033300"}}]'''
                                                                                                                            }
                                                                                                client_event_post_5 = self.session.post('https://api.twitter.com/1.1/jot/client_event.json', headers=client_event_post_5_headers, data=client_event_post_5_data)
                                                                                                if client_event_post_5.status_code == 200 and client_event_post_5.text == '':
                                                                                                    confirm_email_headers = {'host': 'twitter.com', 'content-length': '188', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA', 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/i/flow/login', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
                                                                                                    confirm_email_data = loads(dumps(f'''{{"flow_token":"{flow_token5}","subtask_inputs":[{{"subtask_id":"LoginAcid","enter_text":{{"text":"{challenge_method}","link":"next_link"}}}}]}}'''))
                                                                                                    confirm_email = self.session.post("https://twitter.com/i/api/1.1/onboarding/task.json", headers=confirm_email_headers, data=confirm_email_data)
                                                                                                    if  confirm_email.status_code == 200 and 'status":"success' in confirm_email.text and 'subtask_id":"LoginSuccessSubtask' in confirm_email.text:
                                                                                                        self.__is_logged_in = True
                                                                                                        return [True, self.session]
                                                                                                    else:
                                                                                                        return [False, confirm_email]
                                                                                                else:
                                                                                                    return [False, client_event_post_5]
                                                                                            else:
                                                                                                return [False, client_event_post_4]
                                                                                        # ! if email code verification required
                                                                                        elif ('subtask_id":"LoginAcid' in onboarding_check_duplication.text and 'by entering the email address associated with your Twitter account' not in onboarding_check_duplication.text):
                                                                                            return [False, "Email Verification Code Required."]
                                                                                        elif ('subtask_id":"LoginSuccessSubtask' in onboarding_check_duplication.text):
                                                                                            self.__is_logged_in = True
                                                                                            return [True, self.session]
                                                                                        else:
                                                                                            return [False, onboarding_check_duplication]
                                                                                    else:
                                                                                        return [False, onboarding_check_duplication]
                                                                                elif 'errors":[{"code":399,"message":"Wrong password' in onboarding_password_login.text and onboarding_password_login.status_code == 400:
                                                                                    return [False, "Wrong Password."]
                                                                                elif 'LoginThrowRecaptchaSubtask' in onboarding_password_login.text and onboarding_password_login.status_code == 400:
                                                                                    return [False, "Recaptcha, Try Again!"]
                                                                                else:
                                                                                    return [False, onboarding_password_login]
                                                                            elif 'we could not find your account' in onboarding_user_login.text and onboarding_user_login.status_code == 400:
                                                                                return [False, "Username Not Found."]
                                                                            elif 'LoginThrowRecaptchaSubtask' in onboarding_user_login.text and onboarding_user_login.status_code == 400:
                                                                                return [False, "Recaptcha, Try Again!"]
                                                                                    
                                                                            else:
                                                                                return [False, onboarding_user_login]
                                                                        else:
                                                                            return [False, client_event_post_3]
                                                                    else:
                                                                        return [False, client_event_post_2]
                                                                else:
                                                                    return [False, onboarding_task]
                                                            else:
                                                                return [False, get_ui_metrics]
                                                        else:
                                                            return [False, onboarding_login]
                                                    else:
                                                        return [False, branch_init_post]
                                                else:
                                                    return [False, attribute_post]
                                            else:
                                                return [False, client_event_options_3]
                                        else:
                                            return [False, client_event_post]
                                    else:
                                        return [False, client_event_options_2]
                                else:
                                    return [False, graph_ql]
                            else:
                                return [False, client_event_options]
                        else:
                            return [False, guest_post]
                    else:
                        return [False, guest_options]
                else:
                    return [False, get_home]
            else:
                return [False, get_sw_js]
        else:
            return [False, get_login]

    def get_user_data(self, username: str):
        """ returns the user data for a specific username.
        Args:
            username (str): the username for the account you want to get it's details.

        Returns:
            list: first element is the state of the response. true if the request done successfully and false if some error happened in the request. second element is the data of the user if the request done successfully. or the response of the error request if the request is failed. 
        """
        get_user_info_headers = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'sec-ch-ua': '"Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"', 'DNT': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': '1', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'User-Agent': self.user_agent, 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'no', 'sec-ch-ua-platform': '"Windows"', 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': f'https://twitter.com/{username}', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9', 'Cookie': f'gt={self.guest_token}; ct0=1'}
        get_user_info = self.session.get(f"https://twitter.com/i/api/graphql/B-dCk4ph5BZ0UReWK590tw/UserByScreenName?variables=%7B%22screen_name%22%3A%22{username}%22%2C%22withSafetyModeUserFields%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Afalse%7D",headers=get_user_info_headers)
        if '"data":{"user":' in get_user_info.text and get_user_info.status_code == 200 and 'legacy' in get_user_info.text:
            return [True, get_user_info.json()]
        elif 'Rate limit exceeded' in str(get_user_info.text):
            return [False, "Rate limit exceeded, Please try again later."]
        elif get_user_info.status_code == 200 and 'user' in get_user_info.text and ('User has been suspended' in str(get_user_info.text) or 'reason":"Suspended' in get_user_info.text):
            return [False, "Username suspended."]
        elif '''"message":"Not found''' in str(get_user_info.text) or get_user_info.text == '''{"data":{}}''':
            return [False, "Username not found."]
        else:
            return [False, get_user_info]

    @property
    def log_out(self):
        """A property that ends the current logged in session.
        """
        self.session.close()





twi = Twitter()

