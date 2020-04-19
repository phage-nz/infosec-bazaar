#!/usr/bin/python3

from api.models import BrandEntry
from .config_utils import get_base_config
from django.conf import settings
from .log_utils import get_module_logger
from matplotlib import pyplot as plt


import cv2 as cv
import numpy as np
import os


CDIR = os.path.dirname(os.path.realpath(__file__))
ROOTDIR = os.path.abspath(os.path.join(CDIR, os.pardir))
BASECONFIG = get_base_config(ROOTDIR)
LOGGING = get_module_logger(__name__)


def contains_brand_logo(page_img):
    """Use SIFT to determine if a screenshot contains a known brand logo.

    Params:
    - page_img: (type: string) file path of screenshot.

    Returns:
    - result: (type: string) brand name of match.
    """
    for brand in BrandEntry.objects.all():
        logo_img = os.path.join(settings.MEDIA_ROOT, brand.image.name)

        src_img = cv.imread(page_img, 0)
        template = cv.imread(logo_img, 0)
        w, h = template.shape[::-1]

        threshold = 0.7
        method = cv.TM_CCOEFF_NORMED

        res = cv.matchTemplate(src_img, template, method)
        min_val, max_val, min_loc, max_loc = cv.minMaxLoc(res)

        if max_val > threshold:
            return brand.name

    return False
