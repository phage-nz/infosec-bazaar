#!/usr/bin/python3

from __future__ import division
from api.models import BrandEntry, SearchEntry
from .class_utils import VulnSite
from .config_utils import get_base_config
from .crypto_utils import random_string
from django.conf import settings
from .dns_utils import resolve_dns
from .geo_utils import resolve_asn
from .log_utils import get_module_logger
from random import randint
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from .string_utils import get_host_from_url
from urllib.parse import quote_plus


import cv2
import math
import os
import pyvirtualdisplay
import re
import sys
import time


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


TIMEOUT = 10


def start_webdriver():
    """Initialise a webdriver.

    Return:
    - driver: (type: webdriver) new webdriver object
    """
    LOGGING.info('Configuring Firefox webdriver...')

    options = Options()
    options.set_preference('browser.window.width', 0)
    options.set_preference('browser.window.height', 0)
    options.set_preference('dom.disable_beforeunload', True)
    options.set_preference('dom.popup_maximum', 0)
    options.set_preference('privacy.popups.showBrowserMessage', False)

    driver = webdriver.Firefox(
        firefox_options=options,
        executable_path='/usr/local/bin/geckodriver')
    driver.set_page_load_timeout(30)

    LOGGING.info('Firefox driver initialised!')

    return driver


def restart_webdriver(driver):
    """Restart the webdriver in the case of serious failure.

    Params:
    - driver: (type: webdriver) current webdriver object.

    Return:
    - driver: (type: webdriver) new webdriver object.
    """
    LOGGING.info('Restarting Firefox webdriver...')

    driver.quit()

    return start_webdriver()


def get_num_pages(driver):
    """Determine the number of pages returned by the Google search.

    Params:
    - driver: (type: webdriver) webdriver object.

    Return:
    - pages: (type: int) the number of pages.
    """
    pages = 0

    try:
        result_text = driver.find_element_by_id('resultStats').text
        result_match = re.search(r'(\d{1,}) results', result_text)

        if bool(result_match):
            results = int(result_match.group(1))
            pages = int(math.ceil(results / BASECONFIG.google_batch_size))

    except Exception as e:
        LOGGING.error('Failed to retrieve page count: {0}'.format(str(e)))

    return pages


def extract_links(driver):
    """Search HTML of the current result page for result link targets.

    Params:
    - driver: (type: webdriver) webdriver object.

    Return:
    - link_list: (type: string list) list of link targets.
    """
    link_list = []

    try:
        links = driver.find_elements_by_xpath('//h3//a[@href]')

        for elem in links:
            link = elem.get_attribute('href')

            if 'www.google.co.{0}'.format(
                    BASECONFIG.country.lower()) not in link:
                link_list.append(link)

    except Exception as e:
        LOGGING.error('Failed to extract links: {0}'.format(str(e)))

    return link_list


def get_dork_results(driver, dork_string):
    """Perform a Google search using Selenium.

    Params:
    - driver: (type: webdriver) webdriver object.
    - dork_string: (type: string) Google query to make.

    Return:
    - url_list: (type: string list) list of vulnerable URLs.
    """
    url_list = []

    query = quote_plus(
        '{0} site:{1}'.format(
            dork_string,
            BASECONFIG.country.lower()))
    url_first = 'https://www.google.co.{0}/search?safe=off&q={1}&num={2}&ia=web'.format(
        BASECONFIG.country.lower(), query, str(BASECONFIG.google_batch_size))

    LOGGING.info('Perfoming Google Dork query: {0}'.format(dork_string))

    try:
        LOGGING.info('Requesting: {0}'.format(url_first))
        driver.get(url_first)

        LOGGING.info('Waiting for a moment...')
        time.sleep(randint(10, 20))

        num_pages = get_num_pages(driver)
        result_set = extract_links(driver)

        if len(result_set) > 0:
            url_list.extend(result_set)

            if num_pages > 1:
                for n in range(2, num_pages + 1):
                    start_num = BASECONFIG.google_batch_size * n - BASECONFIG.google_batch_size

                    url_next = 'https://www.google.co.{0}/search?q={1}&safe=off&num={2}&start={3}&ia=web'.format(
                        BASECONFIG.country.lower(), query, str(BASECONFIG.google_batch_size), str(start_num))
                    LOGGING.info('Requesting: {0}'.format(url_next))
                    driver.get(url_next)

                    LOGGING.info('Waiting for a moment...')
                    time.sleep(randint(10, 20))

                    result_set = extract_links(driver)

                    if len(result_set) > 0:
                        url_list.extend(result_set)

    except Exception as e:
        LOGGING.error('Google search failed: {0}'.format(str(e)))
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return url_list


def get_vuln_sites():
    """Wrapper method for get_dork_results.

    Return:
    - site_list: (type: VulnSite list) list of vulnerable site objects.
    """
    site_list = []

    display = pyvirtualdisplay.Display(visible=0, size=(1920, 1080))
    display.start()

    driver = start_webdriver()

    for google_dork in SearchEntry.objects.filter(
            category=SearchEntry.GoogleDork):

        dork_results = get_dork_results(driver, google_dork.term)

        if len(dork_results) > 0:
            for dork_result in dork_results:
                site_host = get_host_from_url(dork_result)
                site_address = resolve_dns(site_host)

                if site_address:
                    asn = resolve_asn(site_address)

                    site_object = VulnSite(
                        site_host,
                        site_address,
                        asn,
                        dork_result,
                        google_dork.reference,
                        'Google Dork')
                    site_list.append(site_object)

    driver.quit()
    display.stop()

    return site_list


def clear_alerts(driver):
    """Interact with and clear alerts on a page.

    Params:
    - driver: (type: webdriver) webdriver object.

    Return:
    - result: (type: string) 'dismissed', 'failed' or 'clear'.
    """
    try:
        WebDriverWait(
            driver,
            TIMEOUT).until(
            EC.alert_is_present(),
            'Timed out waiting for alert to appear.')

        alert = driver.switch_to.alert
        LOGGING.warning('Found alert text: {0}'.format(alert.text))

        try:
            alert.dismiss()
            LOGGING.info('Dismissed alert.')
            return 'dismissed'

        except Exception as e:
            LOGGING.error('Failed to dismiss alert: {0}'.format(str(e)))

            alert = driver.switch_to.alert

            try:
                alert.accept()
                LOGGING.info('Accepted alert.')
                return 'cleared'

            except Exception as e:
                LOGGING.error('Failed to accept alert: {0}'.format(str(e)))
                return 'failed'

    except TimeoutException:
        LOGGING.info('No alert present.')
        return 'clear'


def page_is_ready(driver):
    """Determine if page has completed loading.

    Params:
    - driver: (type: webdriver) webdriver object.

    Return:
    - result: (type: bool) if loading completed.
    """
    for x in range(TIMEOUT):
        try:
            page_state = driver.execute_script('return document.readyState;')

            if page_state == 'complete':
                return True

        except Exception as e:
            LOGGING.warning('Page not ready: {0}'.format(str(e)))

        time.sleep(1)

    return False


def get_site_data(driver, url):
    """Get site screenshot and source using Selenium.

    Params:
    - driver: (type: webdriver) webdriver object.
    - url: (type: string) URL to query.

    Return:
    - file_path: (type: string, False if empty) temporary screenshot path.
    - driver.page_source: (type: string, None if empty) page source.
    - driver_error: (type: bool) restart webdriver if True.
    """
    LOGGING.info('Requesting: {0}'.format(url))

    file_name = '{0}.png'.format(random_string(32))
    file_path = os.path.join(settings.MEDIA_ROOT, 'tmp', file_name)

    try:
        driver.get(url)

        LOGGING.info('Request complete. Checking for alerts...')

        alert_status = clear_alerts(driver)

        if alert_status == 'failed':
            return False, None, True

        elif alert_status == 'dismissed':
            LOGGING.info('Checking for repeat alerts...')

            repeat_alert_status = clear_alerts(driver)

            if repeat_alert_status == 'failed':
                return False, None, True

            elif repeat_alert_status == 'dismissed':
                LOGGING.warning('Alert is repeating. Drastic action required...')

                return False, None, True

        LOGGING.info('Ensuring page is ready for snapshot...')

        page_ready = page_is_ready(driver)

        if page_ready:
            driver.execute_script("document.documentElement.style.height = document.getElementsByTagName('body')[0].clientHeight;")

            LOGGING.info('Taking screenshot...')
            driver.save_screenshot(file_path)

            LOGGING.info('Screenshot successful!')

            return file_path, driver.page_source, False

        else:
            LOGGING.error('Page failed to enter a ready state.')

    except WebDriverException as e:
        LOGGING.error('WebDriver error: {0}'.format(str(e)))

    except Exception as e:
        LOGGING.error('General error: {0}'.format(str(e)))
        LOGGING.exception(sys.exc_info())
        LOGGING.exception(type(e))
        LOGGING.exception(e.args)
        LOGGING.exception(e)

    return False, None, False


def contains_brand_data(site_img, site_source, url):
    """Search screenshot and source for brand data.

    Params:
    - site_img: (type: string, False if empty) temporary screenshot path.
    - site_source: (type: string, None if empty) page source.

    Return:
    - brand.name: (type: string, False if empty) brand name of match.
    """
    if site_img:
        for brand in BrandEntry.objects.all():
            if any(domain in site_source for domain in brand.domains if domain is not None):
                LOGGING.info('Found {0} domain in site source: {1}'.format(brand.name, url))
                clean_up(site_img)
                return brand.name

            logo_img = os.path.join(settings.MEDIA_ROOT, brand.image.name)

            try:
                min_match_count = 20

                src_img = cv2.imread(site_img, 0)
                template = cv2.imread(logo_img, 0)

                sift = cv2.xfeatures2d.SIFT_create()
                kp1, des1 = sift.detectAndCompute(template, None)
                kp2, des2 = sift.detectAndCompute(src_img, None)

                flann_index_kdtree = 0
                index_params = dict(algorithm=flann_index_kdtree, trees=5)
                search_params = dict(checks=50)
                flann = cv2.FlannBasedMatcher(index_params, search_params)
                matches = flann.knnMatch(des1, des2, k=2)

                matched_points = []

                for m,n in matches:
                    if m.distance < 0.7*n.distance:
                        matched_points.append(m)

                if len(matched_points) > min_match_count:
                    LOGGING.info('Found {0} logo in page with {1} matched points: {2}'.format(brand.name, len(matched_points), url))
                    clean_up(site_img)
                    return brand.name

            except Exception as e:
                LOGGING.error('Error performing image match: {0}'.format(str(e)))
                clean_up(site_img)
                return False

        clean_up(site_img)

    else:
        LOGGING.error('Cannot analyse empty page data.')

    return False


def clean_up(file_path):
    """Removes a temporary screenshot file.

    Params:
    - file_path: (type: string) temporary screenshot path.
    """
    if os.path.exists(file_path):
        LOGGING.info('Removing file: {0}'.format(file_path))
        os.remove(file_path)
