__author__ = "Mostafa Abdullhuq (3B7Q)"

from functools import wraps
from multiprocessing import AuthenticationError
import requests
from bs4 import BeautifulSoup
from re import findall
from json import dumps, loads
from re import findall
import requests
from threading import Thread,Lock
from time import sleep, time
from os import system, mkdir, path
import struct
from random import choice
import sys
try:from urllib.parse import quote_plus
except: from urllib import quote_plus




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


    def login_required(func):
        """decorator to ensure that is user is logged in before performing specific action

        Args:
            func (func): A function that performs an action that you want to ensure that user is logged in before doing it.
        """
        def nested_function(self,*args, **kwargs):
            if self.__is_logged_in and self.__is_banned == False and self.__is_suspended == False:
                func(*args, **kwargs)
            else:
                raise AuthenticationError("Account banned, suspended or you are not logged in.")
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
    
    @property
    def time_stamp(self):
        """
        Returns:
            int: the current timestamp
        """
        return round(time() * 1000)

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
                                                                        f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"event_namespace":{{"page":"onboarding","action":"show","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":1,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token}","name":"LoginJsInstrumentationSubtask"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":2,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token}","name":"LoginJsInstrumentationSubtask","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":3,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token2}","name":"LoginEnteruserIdentifierSSOSubtask"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":4,"client_app_id":"3033300"}}]'''
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
                                                                        client_event_post_3_data = {
                                                                            "debug":"true",
                                                                            "log":f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token2}","name":"LoginEnteruserIdentifierSSOSubtask","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":5,"client_app_id":"3033300"}}]''',
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
                                                                                    f"""{{"flow_token": "{flow_token2}","subtask_inputs": [{{"subtask_id": "LoginEnteruserIdentifierSSO","settings_list": {{"setting_responses": [{{"key": "userIdentifier","response_data": {{"text_data": {{"result": "{username}"}}}}}}],"link": "next_link"}}}}]}}"""
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
                                                                                            client_event_post_4_headers = {'host': 'api.twitter.com', 'content-length': '2913', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/x-www-form-urlencoded', 'accept': '*/*', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
                                                                                            client_event_post_4_data = {
                                                                                                'debug':'true',
                                                                                                'log':f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token3}","name":"LoginEnterPassword"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":8,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token3}","name":"LoginEnterPassword","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":9,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token4}","name":"AccountDuplicationCheck"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":10,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token4}","name":"AccountDuplicationCheck","description":"AccountDuplicationCheck_false"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":11,"client_app_id":"3033300"}},{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token5}","name":"LoginAcid"}}],"event_namespace":{{"page":"onboarding","element":"view","action":"impression","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":12,"client_app_id":"3033300"}}]'''
                                                                                                                        }
                                                                                            client_event_post_4 = self.session.post('https://api.twitter.com/1.1/jot/client_event.json', headers=client_event_post_4_headers, data=client_event_post_4_data)
                                                                                            if client_event_post_4.status_code == 200 and client_event_post_4.text == '':
                                                                                                client_event_post_5_headers = {'host': 'api.twitter.com', 'content-length': '2913', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/x-www-form-urlencoded', 'accept': '*/*', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
                                                                                                client_event_post_5_data = {
                                                                                                    'debug':'true',
                                                                                                    'log':f'''[{{"_category_":"client_event","format_version":2,"triggered_on":{self.time_stamp},"items":[{{"token":"{flow_token5}","name":"LoginAcid","description":"next_link"}}],"event_namespace":{{"page":"onboarding","element":"link","action":"click","client":"m5"}},"client_event_sequence_start_timestamp":{self.time_stamp},"client_event_sequence_number":13,"client_app_id":"3033300"}}]'''
                                                                                                                            }
                                                                                                client_event_post_5 = self.session.post('https://api.twitter.com/1.1/jot/client_event.json', headers=client_event_post_5_headers, data=client_event_post_5_data)
                                                                                                if client_event_post_5.status_code == 200 and client_event_post_5.text == '':
                                                                                                    confirm_email_headers = {'host': 'twitter.com', 'content-length': '188', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.26 Safari/537.36 Edg/101.0.1210.14', 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"Windows"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/i/flow/login', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9'}
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

    def get_user_details(self, username: str):
        """ returns the user data for a specific username.
        Args:
            username (str): the username for the account you want to get it's details.

        Returns:
            list: first element is the state of the response. true if the request done successfully and false if some error happened in the request. second element is the data of the user if the request done successfully. or the response of the error request if the request is failed. 
        """
        if self.guest_token == None:
            self.generate_guest_token()
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

    def check_search_banned(self, username: str, proxy= None):
        """check the state of the user by searching for it's tweets.
        Args:
            username (str): the username for the account you want to check it's state.
        Returns:
            list: first element is the state of the request. true if the request done successfully and false if some error happened in the request. second element is the data of the user if the request done successfully. or the response of the error request if the request is failed.\nsuccess state types:
                1 => Good
                2 => Banned
                3 => No Tweets
                4 => Protected
                5 => Suspended
                6 => Not Found
        """
        if self.guest_token == None:
            self.generate_guest_token()
        get_profile_headers = {
            'User-Agent':self.user_agent,
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Sec-Fetch-Site':'none',
            'Sec-Fetch-Mode':'navigate',
            'Sec-Fetch-User':'?1',
            'Sec-Fetch-Dest':'document',
            'Accept-Language':'en-US,en;q=0.9,ar-EG;q=0.8,ar;q=0.7,nl;q=0.6',
        }
        get_profile = self.session.get('https://twitter.com/{}'.format(username),headers=get_profile_headers)
        if get_profile.status_code == 200 :
            graph_ql_options_headers = {
                'Host':'api.twitter.com',
                'Accept':'*/*',
                'Access-Control-Request-Method':'GET',
                'Access-Control-Request-Headers':'authorization,content-type,x-csrf-token,x-guest-token,x-twitter-active-user,x-twitter-client-language',
                'Origin':'https://twitter.com',
                'Sec-Fetch-Mode':'cors',
                'Sec-Fetch-Site':'same-site',
                'Sec-Fetch-Dest':'empty',
                'Referer':'https://twitter.com/{}'.format(username),
                'User-Agent':self.user_agent,
                'Accept-Language':'en-US,en;q=0.9,ar-EG;q=0.8,ar;q=0.7,nl;q=0.6',
            }
            graph_ql_options_params = {
                'variables':str(loads((dumps('{{"screen_name":"{}","withHighlightedLabel":true}}'.format(username)))))
            }
            graph_ql_options = self.session.options('https://api.twitter.com/graphql/-xfUfZsnR_zqjFd-IfrN5A/UserByScreenName?'.format(username.lower()),headers=graph_ql_options_headers,params=graph_ql_options_params)
            if graph_ql_options.status_code == 200:
                graph_ql_get_headers = {
                    'Host':'api.twitter.com',
                    'x-twitter-client-language':'en',
                    'x-csrf-token':'a9b7d0e0fe277ca386decfd4373cdd71',
                    'authorization':f'Bearer {self.bearer_token}',
                    'content-type':'application/json',
                    'User-Agent':self.user_agent,
                    'x-guest-token':'{}'.format(self.guest_token),
                    'x-twitter-active-user':'yes',
                    'Accept':'*/*',
                    'Origin':'https://twitter.com',
                    'Sec-Fetch-Site':'same-site',
                    'Sec-Fetch-Mode':'cors',
                    'Sec-Fetch-Dest':'empty',
                    'Referer':'https://twitter.com/{}'.format(username),
                    'Accept-Language':'en-US,en;q=0.9,ar-EG;q=0.8,ar;q=0.7,nl;q=0.6'
                }
                graph_ql_get_params = {
                    'variables': str(loads((dumps('{{"screen_name":"{}","withHighlightedLabel":true}}'.format(username)))))
                }
                graph_ql_get = self.session.get('https://api.twitter.com/graphql/-xfUfZsnR_zqjFd-IfrN5A/UserByScreenName?'.format(username.lower()),headers=graph_ql_get_headers,params=graph_ql_get_params)
                if graph_ql_get.status_code == 200 and 'user' in str(graph_ql_get.text) and 'created_at' in str(graph_ql_get.text):
                    user_id = graph_ql_get.json()['data']['user']['rest_id']
                    get_tweets_headers = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'authorization': f'Bearer {self.bearer_token}', 'DNT': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': 'a9b7d0e0fe277ca386decfd4373cdd71', 'x-guest-token': '{}'.format(self.guest_token), 'x-twitter-active-user': 'yes', 'User-Agent': self.user_agent, 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/', 'Accept-Language': 'en-US,en;q=0.9', 'Cookie1': 'personalization_id="v1_cvet2wHhji0RQ6jewODqQw=="; guest_id=v1%3A161365290208151861; ct0=41ddc0c5eb88510407b5d30d4f72ca6c; _sl=1; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCP1FNbV3AToMY3NyZl9p%250AZCIlMjA3Y2VjMjliNjhhNGEwOTVmZmRhYWFmODMxOGE5OWI6B2lkIiU1MzEz%250ANDAzNDUxOTliY2E1OTI1MWY4NmY4MWQ3OTQ0MA%253D%253D--180911d4e5b56a30b643927e79cfe9fc4b20fad6; gt='+self.guest_token}
                    get_tweets = self.session.get(f'https://twitter.com/i/api/graphql/DhQ8lYnLh5T5K8aVUgHVnQ/UserTweets?variables=%7B%22userId%22%3A%22{user_id}%22%2C%22count%22%3A40%2C%22includePromotedContent%22%3Atrue%2C%22withQuickPromoteEligibilityTweetFields%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Atrue%2C%22withBirdwatchPivots%22%3Afalse%2C%22withDownvotePerspective%22%3Afalse%2C%22withReactionsMetadata%22%3Afalse%2C%22withReactionsPerspective%22%3Afalse%2C%22withSuperFollowsTweetFields%22%3Atrue%2C%22withVoice%22%3Atrue%2C%22withV2Timeline%22%3Afalse%2C%22__fs_interactive_text%22%3Afalse%2C%22__fs_dont_mention_me_view_api_enabled%22%3Afalse%7D',headers=get_tweets_headers)
                    if 'data' in str(get_tweets.text) and get_tweets.status_code == 200 and 'user' in str(get_tweets.text) and  'UserUnavailable' not in str(get_tweets.text):
                        tweets_ids, search_tweets_ids, users_tweets_ids_list = [], [], []
                        for _ in get_tweets.json()['data']['user']['result']['timeline']['timeline']['instructions'][1]['entries']:
                            if _['content']['entryType'] == 'TimelineTimelineItem':
                                tweets_ids.append(_['sortIndex'])
                        users_tweets_ids_list += tweets_ids
                        if len(tweets_ids) != 0:
                            if '111111111111cursorType":"Bottom' in str(get_tweets.text) and 'cursor":{"value' in str(get_tweets.text):
                                current_cursor = quote_plus(findall(r'\"cursor\"\:\{\"value\"\:\"((\w?\=?\+?\-?\&?\*?\#?\_?\/?\\?)*)\"\,\"cursorType\"\:\"Bottom',str(get_tweets.text))[0][0])
                                is_done_1 = False
                                while True:
                                    get_tweets_headers = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'authorization': f'Bearer {self.bearer_token}', 'DNT': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': 'a9b7d0e0fe277ca386decfd4373cdd71', 'x-guest-token': '{}'.format(self.guest_token), 'x-twitter-active-user': 'yes', 'User-Agent': self.user_agent, 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/', 'Accept-Language': 'en-US,en;q=0.9', 'Cookie1': 'personalization_id="v1_cvet2wHhji0RQ6jewODqQw=="; guest_id=v1%3A161365290208151861; ct0=41ddc0c5eb88510407b5d30d4f72ca6c; _sl=1; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCP1FNbV3AToMY3NyZl9p%250AZCIlMjA3Y2VjMjliNjhhNGEwOTVmZmRhYWFmODMxOGE5OWI6B2lkIiU1MzEz%250ANDAzNDUxOTliY2E1OTI1MWY4NmY4MWQ3OTQ0MA%253D%253D--180911d4e5b56a30b643927e79cfe9fc4b20fad6; gt='+self.guest_token}
                                    get_tweets = self.session.get(f'https://twitter.com/i/api/2/timeline/profile/{user_id}.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_ext_alt_text=true&include_quote_count=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweet=true&include_tweet_replies=false&count=200&cursor={current_cursor}&userId={user_id}&ext=mediaStats%2ChighlightedLabel',headers=get_tweets_headers)
                                    if 'globalObjects' in str(get_tweets.text) and get_tweets.status_code == 200 and 'tweets' in str(get_tweets.text):
                                        new_tweets_ids = list(get_tweets.json()['globalObjects']['tweets'].keys())
                                        if len(new_tweets_ids) == 0:
                                            is_done_1 = True
                                            break
                                        else:
                                            current_cursor = quote_plus(findall(r'\"cursor\"\:\{\"value\"\:\"((\w?\=?\+?\-?\&?\*?\#?\_?\/?\\?)*)\"\,\"cursorType\"\:\"Bottom',str(get_tweets.text))[0][0])
                                            lent = len(list(set(users_tweets_ids_list)))
                                            users_tweets_ids_list += new_tweets_ids
                                            if len(list(set(users_tweets_ids_list))) == lent: is_done_1 = True ; break
                                            continue
                                    elif 'Rate limit exceeded' in str(get_tweets.text):
                                        return [False, "Rate limit exceeded."]
                                    else:
                                        return [False, get_tweets]
                            is_done_1 = True
                            if is_done_1:
                                search_adaptive_get_headers = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'authorization': f'Bearer {self.bearer_token}', 'DNT': '1', 'x-twitter-client-language': 'en', 'x-guest-token': '{}'.format(self.guest_token), 'x-twitter-active-user': 'yes', 'User-Agent': self.user_agent, 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/search?q={}&src=typed_query&f=live'.format(username), 'Accept-Language': 'en-US,en;q=0.9'}
                                search_adaptive_get = self.session.get(f'https://twitter.com/i/api/2/search/adaptive.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_ext_alt_text=true&include_quote_count=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweet=true&q=(from%3A{username})%20-filter%3Areplies&tweet_search_mode=live&count=20&query_source=typed_query&pc=1&spelling_corrections=1&ext=mediaStats%2ChighlightedLabel%2CsignalsReactionMetadata%2CsignalsReactionPerspective%2CvoiceInfo', headers=search_adaptive_get_headers)
                                if 'globalObjects' in search_adaptive_get.text and search_adaptive_get.status_code == 200 and 'tweets' in search_adaptive_get.text:
                                    results_tweets_ids = []
                                    for tweet_id in search_adaptive_get.json()['globalObjects']['tweets']:
                                        if 'Twitter Media Policy' in search_adaptive_get.json()['globalObjects']['tweets'][tweet_id]['full_text']:
                                            break
                                        else:
                                            results_tweets_ids.append(tweet_id)
                                    search_tweets_ids += results_tweets_ids
                                    if len(results_tweets_ids) != 0:
                                        if 'cursorType":"Bottom' in str(search_adaptive_get.text) and 'cursor":{"value' in str(search_adaptive_get.text):
                                            current_cursor2 = quote_plus(findall(r'\"cursor\"\:\{\"value\"\:\"(scroll:(\w?\=?\+?\-?\&?\*?\#?\_?\/?\\?)*)\"',str(search_adaptive_get.text))[0][0])
                                            is_done = False
                                            while True:
                                                search_adaptive_getHeaders = {'Host': 'twitter.com', 'Connection': 'keep-alive', 'authorization': f'Bearer {self.bearer_token}', 'DNT': '1', 'x-twitter-client-language': 'en', 'x-guest-token': '{}'.format(self.guest_token), 'x-twitter-active-user': 'yes', 'User-Agent': self.user_agent, 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/search?q={}&src=typed_query&f=live'.format(username), 'Accept-Language': 'en-US,en;q=0.9'}
                                                search_adaptive_get = self.session.get(f'https://twitter.com/i/api/2/search/adaptive.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_ext_alt_text=true&include_quote_count=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweet=true&q=(from%3A{username})%20-filter%3Areplies&tweet_search_mode=live&count=20&query_source=typed_query&cursor={current_cursor2}&pc=1&spelling_corrections=1&ext=mediaStats%2ChighlightedLabel', headers=search_adaptive_getHeaders)
                                                if 'globalObjects' in str(search_adaptive_get.text) and search_adaptive_get.status_code == 200 and 'tweets' in str(search_adaptive_get.text):
                                                    new_tweets_ids = list(search_adaptive_get.json()['globalObjects']['tweets'].keys())
                                                    if len(new_tweets_ids) == 0:
                                                        is_done = True
                                                        break
                                                    else:
                                                        current_cursor2 = quote_plus(findall(r'\"cursor\"\:\{\"value\"\:\"(scroll:(\w?\=?\+?\-?\&?\*?\#?\_?\/?\\?)*)\"',str(search_adaptive_get.text))[0][0])
                                                        search_tweets_ids += new_tweets_ids
                                                        continue
                                                elif 'Rate limit exceeded' in str(search_adaptive_get.text):
                                                    return [False, "Rate limit exceeded."]
                                                else:
                                                    return [False, search_adaptive_get]
                                            if is_done:
                                                is_tweet_found = False
                                                for each_tweet_id in search_tweets_ids:
                                                    if each_tweet_id in users_tweets_ids_list:
                                                        is_tweet_found = True
                                                        break
                                                    else:
                                                        continue
                                                if len(search_tweets_ids) >= 1 : is_tweet_found = True
                                                if is_tweet_found == True:
                                                    return [True, 1]
                                                else:
                                                    return self.__verify_search_banned(username)
                                            else:
                                                pass
                                        else:
                                            return [False, search_adaptive_get]
                                    else:
                                        return self.__verify_search_banned(username)
                                else:
                                    return [False, search_adaptive_get]
                            else:
                                pass
                        else:
                            return [True, 3]
                    elif 'UserUnavailable' in str(get_tweets.text) or 'Not authorized to view the specified user' in get_tweets.text:
                        return [True, 4]
                    else:
                        return [False, get_tweets]
                elif 'Rate limit exceeded' in str(graph_ql_get.text):
                    return [False, "Rate limit exceeded."]
                elif graph_ql_get.status_code == 200 and 'user' in str(graph_ql_get.text) and 'User has been suspended' in str(graph_ql_get.text):
                    return [True, 5]
                elif '"name":"NotFoundError"' in str(graph_ql_get.text):
                    return [True, 6]
                else:
                    return [False, graph_ql_get]
            else:
                return [False, graph_ql_options]
        else:
            return [False, get_profile]

    def get_username(self, user_id: int):
        """converts user id to username

        Args:
            user_id (int): the user id to convert

        Returns:
            list: first element is a boolean, if True then the second element is the username, if False then the second element is the error
        """
        if self.guest_token == None:
            self.generate_guest_token()
        get_user = self.session.get(f'https://twitter.com/i/api/graphql/_w0cTirS6nTtBhFocRr6Kg/UserByRestId?variables=%7B%22userId%22%3A%22{user_id}%22%2C%22withSafetyModeUserFields%22%3Atrue%2C%22withSuperFollowsUserFields%22%3Atrue%7D', headers={'host': 'twitter.com', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': self.user_agent, 'x-twitter-active-user': 'no', 'sec-ch-ua-platform': '"macOS"', 'accept': '*/*', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/', 'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9', 'x-guest-token':self.guest_token})
        if 'data":{"user":{"result' in get_user.text:
            try:
                return [True, get_user.json()['data']['user']['result']['legacy']['screen_name']]
            except:
                return [False, get_user]
        else:
            return [False, get_user]

    def __verify_search_banned(self, username: str):
        """verifies if the account is banned from search in the check_search_banned function

        Args:
            username (str): the username of the account to check

        Returns:
            list: first element is the state of the request, true if the request done successfully, false if not. second element is the result of the response
            1 => Good
            2 => Banned
        """
        if self.guest_token == None:
            self.generate_guest_token()
        client_event_options = self.session.options('https://api.twitter.com/1.1/jot/client_event.json', headers={'Host': 'api.twitter.com', 'Connection': 'keep-alive', 'Accept': '*/*', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,x-csrf-token,x-guest-token,x-twitter-active-user,x-twitter-client-language', 'Origin': 'https://twitter.com', 'User-Agent': self.user_agent, 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/', 'Accept-Language': 'en-US,en;q=0.9'})
        if client_event_options.status_code == 200 and client_event_options.text == '':
            search_suggestion = self.session.get(f'https://twitter.com/i/api/1.1/search/typeahead.json?q=@{username}&src=search_box&result_type=events%2Cusers%2Ctopics', headers={'Host': 'twitter.com', 'Connection': 'keep-alive', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'DNT': '1', 'x-twitter-client-language': 'en', 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'User-Agent': self.user_agent, 'x-guest-token': self.guest_token, 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"macOS"', 'Accept': '*/*', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Referer': 'https://twitter.com/explore', 'Accept-Language': 'en-US,en;q=0.9'})
            if 'users":[' in search_suggestion.text and search_suggestion.status_code == 200 and 'num_results"' in search_suggestion.text:
                number_of_results = int(search_suggestion.json()['num_results'])
                users_list = search_suggestion.json()['users']
                if number_of_results > 0:
                    is_found = False
                    for each_user in users_list:
                        if username == each_user['screen_name']:
                            is_found = True
                            break
                        else:
                            continue
                    if is_found:
                        return [True, 1]
                    else:
                        return [True, 2]
                else:
                    return [True, 2]
            else:
                return [False, search_suggestion]
        else:
            return [False, search_suggestion]

    @login_required
    def like(self, tweet_id: int, username: str):
        like_post = self.session.post("https://twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet", headers={'host': 'twitter.com', 'content-length': '89', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': self.session.cookies.get_dict()['ct0'], 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': self.user_agent, 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"macOS"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': f'https://twitter.com/{username}/status/{tweet_id}', 'accept-language': 'en-US,en;q=0.9,ar;q=0.8'}, data=loads(dumps(f'''{{"variables":"{{\\"tweet_id\\":\\"{tweet_id}\\"}}","queryId":"lI07N6Otwv1PhnEgXILM7A"}}''')))
        # if like done successfully
        if 'favorite_tweet":"Done' in like_post.text and like_post.status_code == 200:
            return [True, like_post]
        # if user already made a like to the same tweet
        elif 'has already favorited tweet' in like_post.text and like_post.status_code == 200:
            return [False, "Already liked this tweet."]
        # if the tweet already deleted
        elif 'to a Tweet that is deleted or not visible to you' in like_post.text or 'Missing: Tweet record for tweetId:' in like_post.text:
            return [False, "Tweet not found."]
        elif 'bounce_location":"https://twitter.com/account/access' in like_post.text:
            self.__is_banned = True
            return [False, "Account banned."]
        # if another error happened while like
        elif 'Denied by access control: Missing TwitterUserNotSuspended' in like_post.text or 'is suspended, deactivated or offboarded"' in like_post.text:
            self.__is_suspended = True
            return [False, "Account suspended."]
        else:
            return [False, like_post]


    def comment(self, tweet_id: int, comment_text: str):
        comment_post = self.session.post("https://twitter.com/i/api/graphql/22ZmD6h57SAhSmN3dWCB3w/CreateTweet", headers={'host': 'twitter.com', 'content-length': '644', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': self.session.cookies.get_dict()['ct0'], 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': self.user_agent, 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"macOS"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/compose/tweet', 'accept-language': 'en-US,en;q=0.9,ar;q=0.8'}, data=loads(dumps(f'''{{"variables":"{{\\"tweet_text\\":\\"{comment_text}\\",\\"reply\\":{{\\"in_reply_to_tweet_id\\":\\"{tweet_id}\\",\\"exclude_reply_user_ids\\":[]}},\\"media\\":{{\\"media_entities\\":[],\\"possibly_sensitive\\":false}},\\"withDownvotePerspective\\":false,\\"withReactionsMetadata\\":false,\\"withReactionsPerspective\\":false,\\"withSuperFollowsTweetFields\\":true,\\"withSuperFollowsUserFields\\":true,\\"semantic_annotation_ids\\":[],\\"dark_request\\":false,\\"__fs_dont_mention_me_view_api_enabled\\":true,\\"__fs_interactive_text_enabled\\":true,\\"__fs_responsive_web_uc_gql_enabled\\":false,\\"__fs_responsive_web_edit_tweet_api_enabled\\":false}}","queryId":"22ZmD6h57SAhSmN3dWCB3w"}}''',ensure_ascii = False)).encode('utf-8'))
        # if comment done successfully
        if comment_post.status_code == 200 and 'data":{"create_tweet":{"tweet_results' in comment_post.text:
            return [True, comment_post]
        # if the user already commented with the same text
        elif 'Status is a duplicate.' in comment_post.text and comment_post.status_code == 200:
            return [False, "Already commented with the same text."]
        # if the tweet is already deleted
        elif 'to a Tweet that is deleted or not visible to you' in comment_post.text:
            return [False, "Tweet not found."]
        # if another error happens while commenting
        elif 'bounce_location":"https://twitter.com/account/access' in comment_post.text:
            self.__is_banned = True
            return [False, "Account banned."]
        elif 'Denied by access control: Missing TwitterUserNotSuspended' in comment_post.text or 'is suspended, deactivated or offboarded"' in comment_post.text:
            self.__is_suspended = True
            return [False, "Account suspended."]
        else:
            return [False, comment_post]

    def retweet(self, tweet_id: int, username: str):
        retweet_post = self.session.post("https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet", headers={'host': 'twitter.com', 'content-length': '112', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': self.session.cookies.get_dict()['ct0'], 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': self.user_agent, 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"macOS"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': f'https://twitter.com/{username}/status/{tweet_id}', 'accept-language': 'en-US,en;q=0.9,ar;q=0.8'}, data=loads(dumps(f'''{{"variables":"{{\\"tweet_id\\":\\"{tweet_id}\\",\\"dark_request\\":false}}","queryId":"ojPdsZsimiJrUGLR1sjUtA"}}''')))
        # if retweet done successfully
        if retweet_post.status_code == 200 and 'retweet_results":{"result":{"rest_id' in retweet_post.text:
            return [True, retweet_post]
        # if user already retweeted this tweet
        elif 'You have already retweeted this Tweet' in retweet_post.text and retweet_post.status_code == 200 or 'Status is a duplicate' in retweet_post.text:
            return [False, "Already retweeted."]
        # if the tweet is not avaliable (deleted or etc..)
        elif 'to a Tweet that is deleted or not visible to you' in retweet_post.text:
            return [False, "Tweet not found."]
        # if another error happens
        elif 'bounce_location":"https://twitter.com/account/access' in retweet_post.text:
            self.__is_banned = True
            return [False, "Account banned."]
        elif 'Denied by access control: Missing TwitterUserNotSuspended' in retweet_post.text or 'is suspended, deactivated or offboarded"' in retweet_post.text:
            self.__is_suspended = True
            return [False, "Account suspended."]
        else:
            return [False, retweet_post]
        
    def quote(self, tweet_id: int, username: str, quote_text: str):
        self.session.encoding = "utf-8"
        quote_post = self.session.post("https://twitter.com/i/api/graphql/22ZmD6h57SAhSmN3dWCB3w/CreateTweet", headers={'host': 'twitter.com', 'content-length': '640', 'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"', 'dnt': '1', 'x-twitter-client-language': 'en', 'x-csrf-token': self.session.cookies.get_dict()['ct0'], 'sec-ch-ua-mobile': '?0', 'authorization': f'Bearer {self.bearer_token}', 'content-type': 'application/json', 'user-agent': self.user_agent, 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-active-user': 'yes', 'sec-ch-ua-platform': '"macOS"', 'accept': '*/*', 'origin': 'https://twitter.com', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'https://twitter.com/compose/tweet', 'accept-language': 'en-US,en;q=0.9,ar;q=0.8'}
        , data=loads(dumps(f'''{{"variables":"{{\\"tweet_text\\":\\"{quote_text}\\",\\"attachment_url\\":\\"https://twitter.com/{username}/status/{tweet_id}\\",\\"media\\":{{\\"media_entities\\":[],\\"possibly_sensitive\\":false}},\\"withDownvotePerspective\\":false,\\"withReactionsMetadata\\":false,\\"withReactionsPerspective\\":false,\\"withSuperFollowsTweetFields\\":true,\\"withSuperFollowsUserFields\\":true,\\"semantic_annotation_ids\\":[],\\"dark_request\\":false,\\"__fs_dont_mention_me_view_api_enabled\\":true,\\"__fs_interactive_text_enabled\\":true,\\"__fs_responsive_web_uc_gql_enabled\\":false,\\"__fs_responsive_web_edit_tweet_api_enabled\\":false}}","queryId":"22ZmD6h57SAhSmN3dWCB3w"}}''',ensure_ascii = False)).encode('utf-8'))
        # if quote done successfully
        if 'create_tweet":{"tweet_results":{"result":{"rest_id"' in quote_post.text and quote_post.status_code == 200:
            return [True, quote_post]
        # if the tweet is not avaliable (deleted or etc..)
        elif 'to a Tweet that is deleted or not visible to you' in quote_post.text:
            return [False, "Tweet not found."]
        # if user already quoted the tweet
        elif 'Status is a duplicate' in quote_post.text:
            return [False, "Already quoted."]
        # if another error happens while quoting
        elif 'bounce_location":"https://twitter.com/account/access' in quote_post.text:
            self.__is_banned = True
            return [False, "Account banned."]
        elif 'Denied by access control: Missing TwitterUserNotSuspended' in quote_post.text or 'is suspended, deactivated or offboarded"' in quote_post.text:
            self.__is_suspended = True
            return [False, "Account suspended."]
        else:
            return [False, quote_post]


    def log_out(self):
        """A property that ends the current logged in session.
        """
        try:
            self.session.close()
            return True
        except:
            return False





twi = Twitter()

user_name = "m_abdullhuq"


print(twi.like(1400000000000000000))