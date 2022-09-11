from functools import wraps
import requests
from bs4 import BeautifulSoup
from re import findall




class Twitter:
    def __init__(self):
        self.__userAgent = ""

    # get the value of the browser user agent
    def user_agent(self):
        return self.__userAgent

    # set a new value for the browser user agent
    def change_user_agent(self, new_agent):
        self.__userAgent = new_agent
        return "User agent changed successfully."

    # login to the account
    def login(self, username, password, email_address = None):
        pass

    def login_required(self, func):

        def nestedFunc(*args, **kwargs):
            func()

        return nestedFunc










twi = Twitter()

